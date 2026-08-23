/**
 * READ-ONLY live probe against a real SwOS switch.
 *
 * SAFETY: this script only performs GET requests (sys.b, link.b, poe.b, lacp.b,
 * vlan.b, fwd.b, snmp.b, sfp.b, !dhost.b). It NEVER POSTs — no configuration of
 * any kind is sent to the device. Run with:
 *   ../../node_modules/.bin/tsx live-probe.ts [address] [username] [password]
 */
import { SwosClient } from './src/swosClient';
import { createPlatform, detectPlatformFromData } from './src/platform';
import { collectSnapshot, buildMetrics, buildDescriptors } from './src/monitoring';

function formatBps(v: number): string {
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
  let x = v;
  let i = 0;
  while (x >= 1000 && i < units.length - 1) {
    x /= 1000;
    i++;
  }
  return `${x >= 100 ? Math.round(x) : x.toFixed(2)} ${units[i]}`;
}

async function main(): Promise<void> {
  const address = process.argv[2] ?? '10.25.10.4';
  const username = process.argv[3] ?? 'admin';
  const password = process.argv[4] ?? '';

  console.log(`[probe] READ-ONLY probe of ${address} (user=${username}, pw=${password ? 'set' : 'empty'})`);
  console.log('[probe] Only GET requests will be sent. No POSTs, no writes.\n');

  const client = new SwosClient(address, { username, password }, 8000);

  // --- Platform detection (single sys.b GET) -------------------------------------------
  const platform = await createPlatform(client);
  console.log(`[probe] platform: ${platform.type} (${platform.name})`);
  console.log(`[probe] portCount=${await platform.portCount()} hasPoe=${await platform.hasPoe()} hasLacp=${await platform.hasLacp()} hasSnmp=${await platform.hasSnmp()}`);

  const sys = (await client.get('sys.b')) as Record<string, unknown>;
  console.log(`[probe] raw sys.b keys: ${Object.keys(sys).join(', ')}`);
  console.log(`[probe] detection from data: ${JSON.stringify(detectPlatformFromData(sys))}\n`);

  // --- Full snapshot (parallel GETs) ------------------------------------------------------
  const t0 = Date.now();
  const s = await collectSnapshot(client);
  console.log(`[probe] snapshot collected in ${Date.now() - t0} ms\n`);

  console.log('--- System ---');
  console.log(
    JSON.stringify(
      {
        platformType: s.platformType,
        identity: s.identity,
        model: s.model,
        firmwareVersion: s.firmwareVersion,
        macAddress: s.macAddress,
        serialNumber: s.serialNumber,
        uptimeSeconds: s.uptimeSeconds,
        currentIp: s.currentIp,
        addressAcquisition: s.addressAcquisition,
        allowFrom: s.allowFrom || '(none)',
      },
      null,
      2
    )
  );

  console.log(`\n--- Ports (${s.ports.length}) ---`);
  for (const p of s.ports) {
    console.log(`  port ${String(p.port).padStart(2)}: name=${p.name} enabled=${p.enabled} up=${p.linkUp} speed=${p.speedLabel} duplex=${p.duplex} autoNeg=${p.autoNegotiation}`);
  }

  if (s.poe) {
    console.log('\n--- PoE ---');
    for (const p of s.poe) {
      const pw = p.powerW !== null ? `${p.powerW} W` : '-';
      const vv = p.voltageV !== null ? `${p.voltageV} V` : '-';
      const cm = p.currentMa !== null ? `${p.currentMa} mA` : '-';
      console.log(`  port ${String(p.port).padStart(2)}: mode=${p.mode} status=${p.status} power=${pw} voltage=${vv} current=${cm}`);
    }
  }

  if (s.lag) {
    console.log('\n--- LAG/LACP ---');
    for (const p of s.lag) console.log(`  port ${String(p.port).padStart(2)}: mode=${p.mode} group=${p.group || '-'} partner=${p.partnerMac || '-'}`);
  }

  if (s.vlans.length > 0) {
    console.log('\n--- VLAN table ---');
    for (const v of s.vlans) console.log(`  vlan ${v.id}: name=${v.name ?? '-'} members=[${v.members.join(', ')}] igmp=${v.igmpSnooping ? 'on' : 'off'}`);
  }

  if (s.portVlans.length > 0) {
    console.log('\n--- Per-port VLANs ---');
    for (const p of s.portVlans) console.log(`  port ${String(p.port).padStart(2)}: mode=${p.mode} receive=${p.receive} defaultVlan=${p.defaultVlanId ?? '-'} force=${p.forceVlanId}`);
  }

  if (s.snmp !== null) {
    console.log('\n--- SNMP ---');
    console.log(JSON.stringify(s.snmp, null, 2));
  }

  if (s.sfpRows.length > 0) {
    console.log(`\n--- SFP (${s.sfpRows.length} rows) ---`);
    for (const row of s.sfpRows.slice(0, 10)) console.log(`  ${JSON.stringify(row)}`);
  }

  if (s.macs.length > 0) {
    console.log(`\n--- MAC table (${s.macs.length} entries, first 15) ---`);
    for (const e of s.macs.slice(0, 15)) console.log(`  ${e.mac} → ${e.intf || '?'}`);
  }

  // Throughput rates need a second sample — wait ~10s and re-collect (GETs only).
  if (s.portStats) {
    console.log('\n[probe] waiting 10 s for a second stats.b sample to compute live rates…');
    await new Promise((r) => setTimeout(r, 10_000));
    const s2 = await collectSnapshot(client);
    if (s2.portStats) {
      console.log('\n--- Port throughput (live) ---');
      for (const p of s2.portStats) {
        const rx = p.rxBitsPerSec !== null ? formatBps(p.rxBitsPerSec) : '—';
        const tx = p.txBitsPerSec !== null ? formatBps(p.txBitsPerSec) : '—';
        console.log(`  port ${String(p.port).padStart(2)} ${p.name.padEnd(18)} rx=${rx.padStart(14)} tx=${tx}`);
      }
      const tr = s2.totalRxBitsPerSec !== null ? formatBps(s2.totalRxBitsPerSec) : '—';
      const tt = s2.totalTxBitsPerSec !== null ? formatBps(s2.totalTxBitsPerSec) : '—';
      console.log(`  TOTAL rx=${tr} tx=${tt}`);
    }
  }

  // --- Metrics + descriptors (what the webapp would render) ---------------------------------
  const metrics = buildMetrics(s, null, null);
  const descriptors = buildDescriptors(s);
  console.log('\n--- Metric keys emitted ---');
  for (const d of descriptors) {
    const v = metrics[d.key];
    const preview = Array.isArray(v) ? `table(${v.length} rows)` : typeof v === 'object' && v !== null ? JSON.stringify(v).slice(0, 80) : String(v);
    console.log(`  ${d.key.padEnd(28)} [${d.group ?? '-'}] = ${preview}`);
  }

  const missing = descriptors.filter((d) => metrics[d.key] === undefined);
  if (missing.length > 0) {
    console.error(`\n[probe] WARNING: ${missing.length} descriptor(s) without metric value: ${missing.map((m) => m.key).join(', ')}`);
  }

  console.log('\n[probe] DONE — no writes were sent to the device.');
}

main().catch((err) => {
  console.error('[probe] FAILED:', err instanceof Error ? err.message : err);
  process.exit(1);
});
