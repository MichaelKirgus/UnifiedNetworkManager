/**
 * READ-ONLY live probe for a real FRITZ!Box — pins down the actual wire shapes
 * of the web-UI data endpoints against production hardware before release.
 *
 * Usage:  ../../node_modules/.bin/tsx live-probe.ts <address> [username] [password]
 *         (defaults: admin / empty password)
 *
 * GETs ONLY — never writes anything to the box. Prints each endpoint's raw
 * JSON (truncated) + the plugin's parsed view so field names can be verified.
 */

import { FBoxClient } from './src/fboxClient';
import { parseInternetInfo, parseLanInfo, parseOverview, parseSystemInfo, parseWlanInfo } from './src/endpoints';

async function main(): Promise<void> {
  const [address, username = 'admin', password = ''] = process.argv.slice(2);
  if (!address) {
    console.error('usage: live-probe.ts <address> [username] [password]');
    process.exit(1);
  }

  const client = new FBoxClient(address, { username, password }, { timeoutMs: 5000 });
  try {
    await client.login();
    console.log(`✅ logged in to ${address}\n`);
  } catch (err) {
    console.error(`❌ login failed: ${(err as Error).message}`);
    process.exit(1);
  }

  const show = async (label: string, path: string): Promise<unknown> => {
    try {
      const raw = await client.getJson(path);
      if (raw == null) {
        console.log(`\n=== ${label} (${path}) — ABSENT/404 ===`);
        return null;
      }
      const text = JSON.stringify(raw, null, 2);
      console.log(`\n=== ${label} (${path}) — raw (first 1500 chars) ===`);
      console.log(text.length > 1500 ? `${text.slice(0, 1500)}\n… [${text.length - 1500} more chars]` : text);
      return raw;
    } catch (err) {
      console.error(`\n=== ${label} (${path}) — ERROR: ${(err as Error).message}`);
      return null;
    }
  };

  const sys = await show('systeminfo64.json', '/systeminfo64.json');
  if (sys != null) {
    console.log('\n--- parsed system ---');
    console.dir(parseSystemInfo(sys), { depth: null });
  }

  const ovr = await show('overview.lua', '/overview.lua?get_data=1&lang_id=en');
  if (ovr != null) {
    console.log('\n--- parsed overview ---');
    console.dir(parseOverview(ovr), { depth: null });
  }

  const inet = await show('internetinfo.json', '/internetinfo.json');
  if (inet != null) {
    console.log('\n--- parsed internet ---');
    console.dir(parseInternetInfo(inet), { depth: null });
  }

  const lan = await show('laninfo.json', '/laninfo.json');
  if (lan != null) {
    console.log('\n--- parsed LAN ports ---');
    console.dir(parseLanInfo(lan), { depth: null });
  }

  for (const ifname of ['wlan0', 'wlan1', 'wlan2']) {
    const raw = await show(`wlaninfo.json ${ifname}`, `/wlaninfo.json?ifname=${ifname}`);
    if (raw != null) {
      console.log('--- parsed radio ---');
      console.dir(parseWlanInfo(raw, ifname), { depth: null });
    }
  }

  // A few extra endpoints worth knowing about for later phases (P5/P6).
  await show('meshinfo.json', '/meshinfo.json?get_data=1&lang_id=en');
  await show('upnpdesc (TR-064 availability)', '/upnpdesc?id=InternetGatewayDevice');

  console.log('\nprobe complete — no writes were performed.');
}

main().catch((err) => {
  console.error('live probe crashed:', err);
  process.exit(1);
});
