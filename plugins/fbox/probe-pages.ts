import fs from 'fs';
import { FBoxClient } from './src/fboxClient';

const host = process.env.FBOX_HOST ?? '10.255.247.1';
const pw = process.env.FBOX_PW ?? '';
if (!pw) throw new Error('FBOX_PW not set');

async function main() {
  const client = new FBoxClient(host, { username: '', password: pw }, { timeoutMs: 8000 });
  await client.login();
  for (const page of process.argv.slice(2)) {
    try {
      const data = await client.getDataPage(page);
      fs.writeFileSync(`/tmp/fbox-page-${page}.json`, JSON.stringify(data ?? null));
      console.log(`PAGE ${page} -> /tmp/fbox-page-${page}.json (${fs.statSync(`/tmp/fbox-page-${page}.json`).size} bytes)`);
    } catch (e) {
      console.error(`PAGE ${page} FAILED:`, String(e).slice(0, 120));
    }
  }
}

main().catch((e) => { console.error('PROBE FAILED:', String(e).slice(0, 200)); process.exit(1); });
