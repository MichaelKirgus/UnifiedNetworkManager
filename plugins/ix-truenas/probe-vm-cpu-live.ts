/**
 * READ-ONLY live probe — what does libvirt expose OVER SSH for per-VM CPU
 * utilization? Tests `virsh domstats` (vCPU time), guest-agent stats and the
 * custom TrueNAS SCALE socket detection. NEVER mutates anything.
 *
 * Usage (from this folder):
 *   TRUENAS_HOST=10.25.0.10 SSH_PRIVATE_KEY='...' npx tsx probe-vm-cpu-live.ts
 */
import { createSshPool, dynamicSshHostVerifier } from '@unm/plugin-sdk';

const host = process.env['TRUENAS_HOST'] ?? '10.25.0.10';
const port = Number(process.env['SSH_PORT'] ?? 22);
const key = process.env['SSH_PRIVATE_KEY'];
if (!key) { console.error('Set SSH_PRIVATE_KEY (PEM, single-line \\n ok).'); process.exit(1); }

const SOCKETS = ['/var/run/libvirt/libvirt-sock', '/run/truenas_libvirt/libvirt-sock'];

async function main(): Promise<void> {
  const pool = createSshPool();
  try {
    const client = await pool.get(host, port, { username: 'root', privateKey: key }, { hostKeyVerifier: dynamicSshHostVerifier(host, port) });

    // 0. Socket detection (same logic as the plugin's buildVirshCommand).
    const detect = `run_virsh() { if [ -n "$VIRSH_URI" ]; then virsh -c "$VIRSH_URI" "$@"; else virsh "$@"; fi; }
VIRSH_URI=
if ! run_virsh list --name >/dev/null 2>&1; then
  for s in ${SOCKETS.map((s) => `'${s}'`).join(' ')}; do
    if [ -S "$s" ] && virsh -c "qemu+unix:///system?socket=$s" list --name >/dev/null 2>&1; then VIRSH_URI="qemu+unix:///system?socket=$s"; break; fi
  done
fi
echo "URI=\${VIRSH_URI:-stock}"
run_virsh version | head -n 3`;
    const d = await client.exec(detect, { username: 'root', privateKey: key });
    console.log('=== socket detection ===\n' + d.stdout);

    // 1. virsh domstats — default fields (CPU time is the key one).
    const r1 = await client.exec(`run_virsh() { if [ -n "$VIRSH_URI" ]; then virsh -c "$VIRSH_URI" "$@"; else virsh "$@"; fi; }; VIRSH_URI=; if ! run_virsh list --name >/dev/null 2>&1; then for s in ${SOCKETS.map((s) => `'${s}'`).join(' ')}; do if [ -S "$s" ] && virsh -c "qemu+unix:///system?socket=$s" list --name >/dev/null 2>&1; then VIRSH_URI="qemu+unix:///system?socket=$s"; break; fi; done; fi
run_virsh domstats 2>/dev/null | head -n 40`, { username: 'root', privateKey: key });
    console.log('\n=== virsh domstats (default) ===\n' + r1.stdout);

    // 2. domstats with explicit vcpu-total — per-vCPU time breakdown?
    const r2 = await client.exec(`run_virsh() { if [ -n "$VIRSH_URI" ]; then virsh -c "$VIRSH_URI" "$@"; else virsh "$@"; fi; }; VIRSH_URI=; if ! run_virsh list --name >/dev/null 2>&1; then for s in ${SOCKETS.map((s) => `'${s}'`).join(' ')}; do if [ -S "$s" ] && virsh -c "qemu+unix:///system?socket=$s" list --name >/dev/null 2>&1; then VIRSH_URI="qemu+unix:///system?socket=$s"; break; fi; done; fi
run_virsh domstats --vcpu-total 2>/dev/null | head -n 40`, { username: 'root', privateKey: key });
    console.log('\n=== virsh domstats --vcpu-total ===\n' + r2.stdout);

    // 3. Guest agent stats (only works if qemu-guest-agent runs in the guest).
    const r3 = await client.exec(`run_virsh() { if [ -n "$VIRSH_URI" ]; then virsh -c "$VIRSH_URI" "$@"; else virsh "$@"; fi; }; VIRSH_URI=; if ! run_virsh list --name >/dev/null 2>&1; then for s in ${SOCKETS.map((s) => `'${s}'`).join(' ')}; do if [ -S "$s" ] && virsh -c "qemu+unix:///system?socket=$s" list --name >/dev/null 2>&1; then VIRSH_URI="qemu+unix:///system?socket=$s"; break; fi; done; fi
for d in $(run_virsh list --state-running --name 2>/dev/null | head -n 3); do echo "--- $d ---"; run_virsh guestinfo "$d" 2>&1 | head -n 6; done`, { username: 'root', privateKey: key });
    console.log('\n=== virsh guestinfo (agent) ===\n' + r3.stdout);

    // 4. domstats twice with a 2 s gap — prove the CPU-time delta is measurable.
    const sample = `run_virsh() { if [ -n "$VIRSH_URI" ]; then virsh -c "$VIRSH_URI" "$@"; else virsh "$@"; fi; }; VIRSH_URI=; if ! run_virsh list --name >/dev/null 2>&1; then for s in ${SOCKETS.map((s) => `'${s}'`).join(' ')}; do if [ -S "$s" ] && virsh -c "qemu+unix:///system?socket=$s" list --name >/dev/null 2>&1; then VIRSH_URI="qemu+unix:///system?socket=$s"; break; fi; done; fi
run_virsh domstats 2>/dev/null | awk 'NR==1 || /CPU/ {print}'`;
    const a = await client.exec(sample, { username: 'root', privateKey: key });
    console.log('\n=== sample A ===\n' + a.stdout);
    await new Promise((r) => setTimeout(r, 2500));
    const b = await client.exec(sample, { username: 'root', privateKey: key });
    console.log('=== sample B (after 2.5 s) ===\n' + b.stdout);
  } finally {
    pool.closeAll();
  }
}

main().catch((e) => { console.error('FATAL:', e instanceof Error ? e.message : e); process.exit(1); });
