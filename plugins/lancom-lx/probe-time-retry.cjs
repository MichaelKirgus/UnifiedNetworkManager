/** Retry probe for the two flaky APs (run inside the LX plugin container). */
const { snmpGet } = require('@unm/snmp-client');
const L = '.1.3.6.1.4.1.2356.13';

(async () => {
  const targets = [
    { n: 'AP_Zimmer_Michael', h: '10.25.1.3', v: 'v1' },
    { n: 'AP_Ralf', h: '10.28.1.1', v: 'v2c' },
  ];
  for (const d of targets) {
    let ok = false;
    for (let i = 1; i <= 4 && !ok; i++) {
      try {
        const res = await snmpGet(d.h, { version: d.v, community: 'public' }, [L + '.1.18.0', L + '.1.19.0', L + '.1.20.0'], { timeoutMs: 6000, retries: 2 });
        console.log(d.n, 'attempt' + i, '→ OK:', [...res.entries()].map(([k, v]) => k.slice(-5) + '=' + JSON.stringify(v)).join(' | '));
        ok = true;
      } catch (e) {
        console.log(d.n, 'attempt' + i, '→ timeout');
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
  }
})();
