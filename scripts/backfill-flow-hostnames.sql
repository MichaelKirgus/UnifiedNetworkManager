-- One-off: add per-endpoint hostname columns to the flow aggregate tables and
-- backfill hostnames + network names/VLANs from the live inventory (run BEFORE
-- deploying the code that writes these on rollup). Idempotent — safe to re-run.

ALTER TABLE flow_agg_5m ADD COLUMN IF NOT EXISTS "srcHostname" TEXT;
ALTER TABLE flow_agg_5m ADD COLUMN IF NOT EXISTS "dstHostname" TEXT;
ALTER TABLE flow_agg_1h ADD COLUMN IF NOT EXISTS "srcHostname" TEXT;
ALTER TABLE flow_agg_1h ADD COLUMN IF NOT EXISTS "dstHostname" TEXT;

-- ── Hostnames from the live hosts inventory (newest lastSeenAt wins per ip) ──

WITH named AS (
  SELECT DISTINCT ON (ip) ip, hostname
  FROM hosts
  WHERE ip <> '' AND hostname IS NOT NULL AND hostname <> ''
  ORDER BY ip, "lastSeenAt" DESC NULLS LAST
)
UPDATE flow_agg_5m f SET "srcHostname" = n.hostname
FROM named n WHERE n.ip = host(f."srcIp") AND f."srcHostname" IS NULL;

WITH named AS (
  SELECT DISTINCT ON (ip) ip, hostname
  FROM hosts
  WHERE ip <> '' AND hostname IS NOT NULL AND hostname <> ''
  ORDER BY ip, "lastSeenAt" DESC NULLS LAST
)
UPDATE flow_agg_5m f SET "dstHostname" = n.hostname
FROM named n WHERE n.ip = host(f."dstIp") AND f."dstHostname" IS NULL;

WITH named AS (
  SELECT DISTINCT ON (ip) ip, hostname
  FROM hosts
  WHERE ip <> '' AND hostname IS NOT NULL AND hostname <> ''
  ORDER BY ip, "lastSeenAt" DESC NULLS LAST
)
UPDATE flow_agg_1h f SET "srcHostname" = n.hostname
FROM named n WHERE n.ip = host(f."srcIp") AND f."srcHostname" IS NULL;

WITH named AS (
  SELECT DISTINCT ON (ip) ip, hostname
  FROM hosts
  WHERE ip <> '' AND hostname IS NOT NULL AND hostname <> ''
  ORDER BY ip, "lastSeenAt" DESC NULLS LAST
)
UPDATE flow_agg_1h f SET "dstHostname" = n.hostname
FROM named n WHERE n.ip = host(f."dstIp") AND f."dstHostname" IS NULL;

-- ── Network name + VLAN via longest-prefix inventory match (set_masklen
--    tolerates inventoried rows whose ip carries host bits, e.g. 10.31.0.2/16) ──

WITH nets AS (
  SELECT ip::inet AS net_ip, prefix, name, "vlanId"
  FROM networks WHERE version = 'v4' AND ip <> '' AND prefix IS NOT NULL
),
matched_src AS (
  SELECT DISTINCT ON (f.ctid) f.ctid, n.name, n."vlanId"
  FROM flow_agg_5m f JOIN nets n ON f."srcIp" << set_masklen(n.net_ip, n.prefix)
  ORDER BY f.ctid, n.prefix DESC
)
UPDATE flow_agg_5m f SET "srcNetworkName" = m.name, "srcVlanId" = m."vlanId"
FROM matched_src m WHERE m.ctid = f.ctid AND f."srcNetworkName" IS NULL;

WITH nets AS (
  SELECT ip::inet AS net_ip, prefix, name, "vlanId"
  FROM networks WHERE version = 'v4' AND ip <> '' AND prefix IS NOT NULL
),
matched_dst AS (
  SELECT DISTINCT ON (f.ctid) f.ctid, n.name, n."vlanId"
  FROM flow_agg_5m f JOIN nets n ON f."dstIp" << set_masklen(n.net_ip, n.prefix)
  ORDER BY f.ctid, n.prefix DESC
)
UPDATE flow_agg_5m f SET "dstNetworkName" = m.name, "dstVlanId" = m."vlanId"
FROM matched_dst m WHERE m.ctid = f.ctid AND f."dstNetworkName" IS NULL;

WITH nets AS (
  SELECT ip::inet AS net_ip, prefix, name, "vlanId"
  FROM networks WHERE version = 'v4' AND ip <> '' AND prefix IS NOT NULL
),
matched_src1h AS (
  SELECT DISTINCT ON (f.ctid) f.ctid, n.name, n."vlanId"
  FROM flow_agg_1h f JOIN nets n ON f."srcIp" << set_masklen(n.net_ip, n.prefix)
  ORDER BY f.ctid, n.prefix DESC
)
UPDATE flow_agg_1h f SET "srcNetworkName" = m.name, "srcVlanId" = m."vlanId"
FROM matched_src1h m WHERE m.ctid = f.ctid AND f."srcNetworkName" IS NULL;

WITH nets AS (
  SELECT ip::inet AS net_ip, prefix, name, "vlanId"
  FROM networks WHERE version = 'v4' AND ip <> '' AND prefix IS NOT NULL
),
matched_dst1h AS (
  SELECT DISTINCT ON (f.ctid) f.ctid, n.name, n."vlanId"
  FROM flow_agg_1h f JOIN nets n ON f."dstIp" << set_masklen(n.net_ip, n.prefix)
  ORDER BY f.ctid, n.prefix DESC
)
UPDATE flow_agg_1h f SET "dstNetworkName" = m.name, "dstVlanId" = m."vlanId"
FROM matched_dst1h m WHERE m.ctid = f.ctid AND f."dstNetworkName" IS NULL;

-- ── Result summary ───────────────────────────────────────────────────────────

SELECT 'flow_agg_5m' AS t, count(*) FILTER (WHERE "srcHostname" IS NOT NULL OR "dstHostname" IS NOT NULL) AS with_hostname,
       count(*) FILTER (WHERE "srcNetworkName" IS NOT NULL OR "dstNetworkName" IS NOT NULL) AS with_netname FROM flow_agg_5m
UNION ALL
SELECT 'flow_agg_1h', count(*) FILTER (WHERE "srcHostname" IS NOT NULL OR "dstHostname" IS NOT NULL),
       count(*) FILTER (WHERE "srcNetworkName" IS NOT NULL OR "dstNetworkName" IS NOT NULL) FROM flow_agg_1h;
