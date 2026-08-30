/** Dump the RAW /data.lua answers for boxnet + boxnet_ipv6 (single login). */
import fs from 'fs';
import { FBoxClient } from './src/fboxClient';

const host = process.env.FBOX_HOST ?? '10.255.247.1';
const pw = process.env.FBOX_PW ?? '';

async function main() {
  const c = new FBoxClient(host, { username: '', password: pw }, { timeoutMs: 8000 });
  await c.login();
  for (const page of ['boxnet', 'boxnet_ipv6']) {
    const res = await (c as any).rawPost('/data.lua', { page, sid: (c as any).sid });
    const body = res.body.toString('utf8');
    fs.writeFileSync(`/tmp/fbox-raw3-${page}.html`, body);
    console.log(`=== ${page}: status=${res.status} len=${body.length}`);
    console.log('head:', JSON.stringify(body.slice(0, 160)));
    console.log('tail:', JSON.stringify(body.slice(-120)));
  }
}

main().catch((e) => {
  console.error('FAIL', e instanceof Error ? e.message : String(e));
  process.exit(1);
});
