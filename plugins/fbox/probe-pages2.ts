import fs from 'fs';
import { FBoxClient } from './src/fboxClient';

const host = process.env.FBOX_HOST ?? '10.255.247.1';
const pw = process.env.FBOX_PW ?? '';

async function main() {
  const client = new FBoxClient(host, { username: '', password: pw }, { timeoutMs: 8000 });
  await client.login();
  const tries: [string, Record<string, string>][] = [
    ['boxnet', {}],
    ['boxnet', { target: 'ipv4-config' }],
    ['boxnet', { config: 'ipv4' }],
    ['boxnet_ipv6', {}],
    ['boxnet_ipv6', { target: 'ipv6-config' }],
  ];
  for (const [page, extra] of tries) {
    try {
      const data = await client.getDataPage(page, extra);
      const tag = `${page}${Object.keys(extra).length ? '_' + JSON.stringify(extra) : ''}`;
      fs.writeFileSync(`/tmp/fbox-page-${tag}.json`, JSON.stringify(data ?? null));
      console.log(`PAGE ${tag} -> ${fs.statSync(`/tmp/fbox-page-${tag}.json`).size} bytes`);
    } catch (e) {
      console.error(`PAGE ${page} ${JSON.stringify(extra)} FAILED:`, String(e).slice(0, 100));
    }
  }
}

main().catch((e) => { console.error('PROBE FAILED:', String(e).slice(0, 200)); process.exit(1); });
