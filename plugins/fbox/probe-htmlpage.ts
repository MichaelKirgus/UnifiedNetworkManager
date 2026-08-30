/** Direct getHtmlPage() check against the live box (single login). */
import { FBoxClient } from './src/fboxClient';
import { parseHtml2BoxNet, parseHtml2BoxNetIpv6 } from './src/endpoints';

const host = process.env.FBOX_HOST ?? '10.255.247.1';
const pw = process.env.FBOX_PW ?? '';

async function main() {
  const c = new FBoxClient(host, { username: '', password: pw }, { timeoutMs: 8000 });
  await c.login();
  for (const page of ['boxnet', 'boxnet_ipv6']) {
    const html = await c.getHtmlPage(page);
    console.log(`=== ${page}: getHtmlPage →`, html == null ? 'NULL' : `string len=${html.length}`);
    if (html != null) {
      if (page === 'boxnet') console.log('  parsed:', JSON.stringify(parseHtml2BoxNet(html)));
      else console.log('  parsed:', JSON.stringify(parseHtml2BoxNetIpv6(html)));
    }
  }
}

main().catch((e) => {
  console.error('FAIL', e instanceof Error ? e.message : String(e));
  process.exit(1);
});
