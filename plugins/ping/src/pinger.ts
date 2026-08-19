import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

export interface PingResult {
  /** True when at least one reply was received. */
  reachable: boolean;
  /** Average round-trip time in ms (null when no replies). */
  avgMs: number | null;
  /** Standard deviation of the RTT samples in ms (null with < 2 replies). */
  jitterMs: number | null;
  /** Packet loss percentage, 0–100. */
  lossPercent: number;
  /** Sent / received packet counts from the ping summary. */
  sent: number;
  received: number;
  /** Set when the ping binary itself failed to run (vs. simple unreachability). */
  error?: string;
}

/**
 * Runs a system ICMP ping against `host` and parses the result.
 *
 * Uses the iputils/GNU `ping` available in the plugin container:
 *   ping -c <count> -W <timeoutSec> <host>
 * The summary line ("4 packets transmitted, 4 received, 0% packet loss") is
 * parsed for sent/received/loss; per-reply "time=NN.N ms" values feed avg and
 * jitter. Works on IPv4 and IPv6 targets alike (ping resolves the name).
 */
export async function pingHost(
  host: string,
  count: number,
  timeoutMs: number
): Promise<PingResult> {
  const timeoutSec = Math.max(1, Math.round(timeoutMs / 1000));

  let stdout = '';
  try {
    ({ stdout } = await execFileAsync('ping', ['-c', String(count), '-W', String(timeoutSec), host], {
      timeout: (timeoutMs + 2000) * count, // hard cap so a wedged ping can't hang the poll
      maxBuffer: 1024 * 512,
    }));
  } catch (err) {
    const e = err as { code?: number | string; stdout?: string; message?: string };
    // Exit code 1 is "some/all packets lost" — still a valid measurement.
    if (e.code === 1 && typeof e.stdout === 'string') {
      stdout = e.stdout;
    } else {
      return {
        reachable: false,
        avgMs: null,
        jitterMs: null,
        lossPercent: 100,
        sent: count,
        received: 0,
        error: (e.message ?? 'ping failed').replace(/\s+/g, ' ').trim(),
      };
    }
  }

  // Per-reply RTT samples: "64 bytes from ... icmp_seq=1 ttl=64 time=12.3 ms"
  const rttValues: number[] = [];
  for (const m of stdout.matchAll(/time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms/g)) {
    const v = Number(m[1]);
    if (Number.isFinite(v)) rttValues.push(v);
  }

  // Summary line: "4 packets transmitted, 3 received, 25.0% packet loss"
  let sent = count;
  let received = rttValues.length;
  let lossPercent = 100;
  const summary = stdout.match(/(\d+)\s+packets?\s+transmitted,\s*(\d+)\s+(?:\(.*?,\s*)?received(?:,|\s)/);
  if (summary) {
    sent = Number(summary[1]) || count;
    received = Number(summary[2]);
  }
  const lossMatch = stdout.match(/([0-9]+(?:\.[0-9]+)?)\s*%\s+packet\s+loss/);
  if (lossMatch) {
    lossPercent = Number(lossMatch[1]);
  } else if (sent > 0) {
    lossPercent = Math.round(((sent - received) / sent) * 1000) / 10;
  }

  const avgMs = rttValues.length > 0 ? round2(rttValues.reduce((a, b) => a + b, 0) / rttValues.length) : null;
  let jitterMs: number | null = null;
  if (rttValues.length >= 2 && avgMs !== null) {
    const variance = rttValues.reduce((acc, v) => acc + (v - avgMs) ** 2, 0) / rttValues.length;
    jitterMs = round2(Math.sqrt(variance));
  }

  return {
    reachable: received > 0,
    avgMs,
    jitterMs,
    lossPercent: Math.min(100, Math.max(0, lossPercent)),
    sent,
    received,
  };
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}
