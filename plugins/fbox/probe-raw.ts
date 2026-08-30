import { FBoxClient } from './src/fboxClient';
const host = process.env.FBOX_HOST ?? '10.255.247.1';
const pw = process.env.FBOX_PW ?? '';
async function main() {
  const c = new FBoxClient(host, { username: '', password: pw }, { timeoutMs: 8000 });
  await c.login();
  for (const page of ['boxnet', 'boxnet_ipv6']) {
    const res = await (c as any).rawPost('/data.lua', { page, sid: (c as any).sid });
    const body = res.body.toString('utf8');
    console.log(`=== ${page}: status=${res.status} len=${body.length}`);
    console.log(body.slice(0, 400));
  }
}
main().catch((e) => { console.error('FAIL', String(e).slice(0, 200)); process.exit(1); });
