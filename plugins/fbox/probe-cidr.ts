/** One-shot live check of the new CIDR + IPv6 metrics (single login). */
import { FBoxClient } from './src/fboxClient';
import { getMonitoring, buildMetrics } from './src/monitoring';

const host = process.env.FBOX_HOST ?? '10.255.247.1';
const pw = process.env.FBOX_PW ?? '';

async function main() {
  const t0 = Date.now();
  const res = await getMonitoring(host, { username: '', password: pw }, { transport: 'auto', requestTimeoutMs: 3000 });
  console.log(`poll took ${Date.now() - t0} ms`);
  console.log('warnings:', res.warnings.length ? res.warnings : '(none)');
  const s = res.snapshot;
  console.log('lanV4:', JSON.stringify(s.lanV4));
  console.log('lanV6Nets:', JSON.stringify(s.lanV6Nets));
  console.log('internet.ipv6Ip:', s.internet?.ipv6Ip, '| ipv6Prefix:', s.internet?.ipv6Prefix);
  const m = buildMetrics(s);
  console.log('networks metric:', JSON.stringify(m['networks'], null, 1));
  console.log('wan.ipv6:', m['wan.ipv6'], '| wan.ipv6Prefix:', m['wan.ipv6Prefix']);
}

main().catch((e) => {
  console.error('FAIL', e instanceof Error ? e.message : String(e));
  process.exit(1);
});
