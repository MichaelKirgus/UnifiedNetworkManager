import { FBoxClient } from './src/fboxClient';

const host = process.env.FBOX_HOST ?? '10.255.247.1';
const pw = process.env.FBOX_PW ?? '';

async function main() {
  const pages: [string, Record<string, string>][] = [['', {}], ['netDev', { xhrId: 'all' }], ['wSet', {}], ['energy', {}], ['usbOv', {}]];

  // Round A: parallel (current behavior) — 3 rounds
  for (const round of [1, 2, 3]) {
    const c = new FBoxClient(host, { username: '', password: pw }, { timeoutMs: 3000 });
    await c.login();
    const t0 = Date.now();
    const results = await Promise.all(pages.map(async ([p, x]) => {
      try {
        const d = await (c as any).rawPost('/data.lua', { ...(p ? { page: p } : {}), sid: (c as any).sid, ...x });
        let null_ = false;
        try { const j = JSON.parse(d.body.toString('utf8')); null_ = !j.data; } catch { null_ = true; }
        return [p || '(home)', d.status, null_ ? 'NULL' : 'ok'];
      } catch (e) { return [p || '(home)', 'ERR', String(e).slice(0, 40)]; }
    }));
    console.log(`PARALLEL round ${round} (${Date.now() - t0}ms):`, results.map((r) => `${r[0]}=${r[2]}`).join(' '));
    await new Promise((r) => setTimeout(r, 1500));
  }

  // Round B: sequential — 3 rounds
  for (const round of [1, 2, 3]) {
    const c = new FBoxClient(host, { username: '', password: pw }, { timeoutMs: 3000 });
    await c.login();
    const t0 = Date.now();
    const out: string[] = [];
    for (const [p, x] of pages) {
      try {
        const d = await (c as any).rawPost('/data.lua', { ...(p ? { page: p } : {}), sid: (c as any).sid, ...x });
        let null_ = false;
        try { const j = JSON.parse(d.body.toString('utf8')); null_ = !j.data; } catch { null_ = true; }
        out.push(`${p || '(home)'}=${null_ ? 'NULL' : 'ok'}`);
      } catch (e) { out.push(`${p || '(home)'}=ERR`); }
    }
    console.log(`SEQ round ${round} (${Date.now() - t0}ms):`, out.join(' '));
    await new Promise((r) => setTimeout(r, 1500));
  }
}

main().catch((e) => { console.error('FAIL', String(e)); process.exit(1); });
