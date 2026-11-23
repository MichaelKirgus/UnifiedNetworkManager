# Flows — sFlow / NetFlow traffic visibility & security insights

The Flows feature ingests flow telemetry from the `flow-collector` plugin, rolls it up into queryable aggregate tiers, and runs deterministic security detectors over both the flow aggregates and the DNS query logs pushed by resolver plugins. Findings land in one shared table (`flow_security_findings`) with a single notification + automation pipeline.

## Architecture

- **Ingest** — `plugins/flow-collector` (UDP 6343) parses sFlow v1/5 and NetFlow v5/v9, pre-aggregates over rolling windows and POSTs batches to the API (`POST /plugin/flows`). Parsers store REPORTED/sampled bytes; the sampling rate is applied exactly once at rollup time (`estBytes = SUM(bytes) × MAX(sampleRate)`).
- **Rollups** — `api/src/workers/flows.ts` (leader key 9011): queue → `flow_micro` (raw, weekly RANGE partitions) → enriched 5-minute tier `flow_agg_5m` (classification, GeoIP, hostname/device joins) → hourly SQL rollup `flow_agg_1h`.
- **Classification** — settings-driven (`utils/ipClassification.ts`): exact inventory hit → special non-routable → inventoried network CIDR → external range list → internal range list → other public = internet. Settings: `flowInternalRanges` (default RFC1918), `flowExternalRanges`.
- **Routes** — `/v1/flows/top-talkers|internet|pairs|timeseries`, `/v1/flow-collectors`, `/v1/flows/security` (+ `/baseline/reset`). Permission `flows:read`; the baseline reset is `system:write`.

## Security detectors

All findings share `flow_security_findings`: one row per distinct condition while active (upserted on re-observation), auto-resolved 24 h after last observation, pruned by `flowSecurityFindingsRetentionDays`. A finding raises ONE notification when first detected and can drive automation rules via the `securityFinding` trigger.

| Kind | Worker | Condition |
|---|---|---|
| `new-destination` | flowSecurity (9021) | Internal source → internet destination IP never seen before in either agg tier. Always recorded; notification gated by `flowSecurityNewDstAlertMinBytes` of volume in the triggering window. |
| `port-scan` | flowSecurity | One internal source talking to ≥ `flowSecurityScanMinDsts` distinct destinations within a single 5-minute bucket (critical at 3×). |
| `egress-baseline` | flowSecurity | A pair's average per-hour rate inside a rolling window (`flowSecurityEgressWindowHours`) exceeds its historical per-hour median (lookback `flowSecurityEgressBaselineDays` over the hourly tier) by ≥ `flowSecurityEgressBaselineMultiple`, above the `flowSecurityEgressMinBytes` floor. Pairs without history are not flagged here (detector 1's job). |
| `beacon` | flowSecurity | A pair active in ≥ `flowSecurityBeaconMinBuckets` distinct 5-minute buckets inside a rolling window (`flowSecurityBeaconWindowHours`) with near-constant spacing — inter-bucket jitter ≤ `flowSecurityBeaconMaxJitterPercent` (coefficient of variation ×100). The classic C2 check-in signature. Perfectly periodic activity over ≥ 2× the minimum count escalates to critical. Sustained heavy transfers are excluded via `flowSecurityBeaconMaxAvgBytesPerBucket` (that's detector 3's domain — beacons are small keep-alives). |
| `ioc-hit` / `dns-ioc-hit` | threatIntel (9023) | Flow destinations / firewall-event IPs vs active IP indicators; queried domains vs domain-list feeds. Per-feed severity applies (`worstSeverity`). |
| `dga` | dnsSecurity (9030) | A client queried a domain whose longest non-TLD label looks algorithmically generated: length ≥ `dnsSecurityDgaMinLabelLen` AND Shannon entropy ≥ `dnsSecurityDgaMinEntropyX10`/10 AND vowel ratio ≤ `dnsSecurityDgaMaxVowelRatioPercent`. All three gates must hold, plus two noise filters: the domain's base zone is not in `dnsSecurityDgaBaseDomainWhitelist`, and the client queried ≥ `dnsSecurityDgaMinDistinctDomainsPerClient` DISTINCT DGA-like domains inside `dnsSecurityDgaVolumeWindowHours` (confirmed clients report every new domain immediately). Each (client, domain) tuple raises at most one finding per process boot. |
| `dns-tunnel` | dnsSecurity | One client issued ≥ `dnsSecurityTunnelMinQueries` subdomain-bearing queries to the same base domain inside a rolling window (`dnsSecurityTunnelWindowHours`) whose subdomain labels average ≥ `dnsSecurityTunnelMinAvgLabelLen` characters — data encoded in DNS names (tunneling / exfiltration). |
| `log-rule` | logRules (9028) | Sigma rule matches over ingested device log lines. |

### Beacon detector notes

- Buckets are 5-minute slots, so a beacon with any sub-5-minute period shows up in **every** bucket (interval = 1 unit); longer periods show up every k-th bucket. The reported `periodMinutes` is the mean interval × 5.
- Per-pair history is in-memory only (rolling window, capped at 200k pairs) — a restart re-baselines from scratch and old periodicity is not re-evaluated.
- The verdict math (`beaconVerdict`) is pure and unit-tested in `api/src/workers/flowSecurity.test.ts`.

### DNS heuristics notes

- Source data: `dns_query_events` — per-query rows pushed by plugins via `POST /plugin/dns-queries` (OPNsense unbound qstats today; any resolver log can be adapted). `client` is verbatim from the appliance (IP or reverse-resolved hostname); findings need an INET source, so hostname clients are resolved through the hosts table — unresolvable clients stay visible in the DNS view but raise no finding.
- Watermark convention: rows with `tsMs` ≤ boot time are never scanned (no history replay). Only `action = 'pass'` rows count — a blocked query was already stopped by blocklists and is not evidence of compromise.
- The DGA gate thresholds were chosen against real human words: `stackoverflow` (entropy ≈ 3.55, vowel ratio 31%) and `acknowledgement` (≈ 3.46, 33%) both stay below the defaults; random lowercase strings sit near entropy 4.7 with low vowel ratios. Tune via settings if your network produces false positives/misses.
- **Noise filters learned from live operation** — string gates alone flagged legitimate cloud naming: OneDrive-for-Business endpoints (`onedsc…westus.cloudapp.azure.com`), CloudFront distribution ids, k8s-generated ELB names on `amazonaws.com`, Alexa device services on `a2z.com`. Two layers now suppress that:
  - **Base-domain whitelist** (`dnsSecurityDgaBaseDomainWhitelist`): comma-separated domains; a query matches when its domain equals an entry or sits under it (suffix match, so `cloudapp.azure.com` covers every OneDrive endpoint even though the last-two-labels base is `azure.com`). Whitelisted zones are never scored — malware cannot register subdomains on someone else's zone, so nothing real is lost.
  - **Volume gate** (`dnsSecurityDgaMinDistinctDomainsPerClient`, default 10, over a rolling `dnsSecurityDgaVolumeWindowHours` window): a client must query that many DISTINCT DGA-like domains before any of them are reported. Real DGA campaigns generate dozens to hundreds of names per host; legit services produce a handful (the OneDrive FP above was 3 distinct endpoints in 25 min). Once confirmed, a client reports every new DGA-like domain for the rest of the boot — set the threshold to 1 to restore report-on-first-sight.
- Base domain = last two labels (naive registered-domain approximation — `co.uk`-style TLDs are not special-cased).

## Settings

| Key | Default | Meaning |
|---|---|---|
| `flowSecurityEnabled` | true | Master switch for the flow-based detectors. |
| `flowSecurityNewDstAlertMinBytes` | 1 MiB | Volume gate for new-destination notifications (0 = every one). |
| `flowSecurityScanMinDsts` | 10 | Distinct destinations per bucket for port-scan candidates. |
| `flowSecurityEgressWindowHours` / `…MinBytes` / `…BaselineDays` / `…Multiple` | 6 h / 245 MiB / 14 d / 3× | Sustained-egress detector tuning. |
| `flowSecurityBeaconMinBuckets` | 6 | Active buckets required inside the beacon window. |
| `flowSecurityBeaconMaxJitterPercent` | 25 | Max inter-bucket jitter (CV ×100). 0 = perfectly periodic only. |
| `flowSecurityBeaconWindowHours` | 24 | Rolling window for beacon history. |
| `flowSecurityBeaconMaxAvgBytesPerBucket` | 4 MiB | Pairs above this average per active bucket are not beacons (heavy transfer). |
| `dnsSecurityEnabled` | true | Master switch for the DNS heuristic detectors. |
| `dnsSecurityDgaMinLabelLen` / `…MinEntropyX10` / `…MaxVowelRatioPercent` | 12 / 36 (=3.6) / 25 | The three AND-gates of the DGA detector. |
| `dnsSecurityDgaMinDistinctDomainsPerClient` / `…VolumeWindowHours` | 10 / 24 h | DGA volume gate — distinct DGA-like domains per client before reporting (1 = report on first sight). |
| `dnsSecurityDgaBaseDomainWhitelist` | cloud/CDN zones (OneDrive, CloudFront, AWS, Alexa, …) | Domains never scored as DGA (suffix match); extend when a new service false-positives. |
| `dnsSecurityTunnelWindowHours` / `…MinQueries` / `…MinAvgLabelLen` | 1 h / 30 / 24 | Tunneling detector tuning. |
| `flowSecurityFindingsRetentionDays` | 30 | Finding row retention (from lastSeenAt). |

All have `UNM_*` env-var overrides (see `api/src/systemSettings.ts`).

## Webapp

- **Flows page → Security section** — findings table with kind/severity pills, source/destination, detail and context; worker status line for both the flow-security worker and the DNS heuristics worker (`GET /v1/flows/security` returns `worker` + `dnsHeuristics`).
- **Automations** — the `securityFinding` trigger can filter by any finding kind (all nine) and template tokens `{{finding.kind|srcIp|dstIp|severity|detail}}`.

## E2E / verification

- `scripts/e2e-flows.cjs` — full multi-protocol ingest pipeline (sFlow + NetFlow v5/v9 in parallel), asserts the sampling-rate-once semantics.
- `scripts/verify-netflow-parser.cjs` / `verify-sflow-parser.cjs` — parser unit tests against reference captures.
- `scripts/e2e-flow-security.ts` — Phase 1 detectors (new-destination, port-scan, egress-baseline) + automation trigger; seeds agg tiers directly and waits out the bucket process lag (~15–18 min).
- `scripts/e2e-flow-security-phase2.ts` — beaconing (periodic positive + high-jitter + heavy-transfer negatives) and DNS heuristics (DGA positive/negative, tunneling positive/negative); test identities in reserved ranges (10.99.1.x sources, TEST-NET-3 dsts, `.test`/`.example` domains).
- Unit tests: `api/src/workers/flowSecurity.test.ts` (`egressVerdict`, `beaconVerdict`) and `api/src/workers/dnsSecurity.test.ts` (entropy, DGA gates, base-domain decomposition, tunnel verdict).
