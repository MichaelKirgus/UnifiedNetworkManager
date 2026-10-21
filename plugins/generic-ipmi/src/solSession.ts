/**
 * SOL (Serial-over-LAN) console session — SshTerminalSession-compatible
 * EventEmitter wrapping an IpmiClient's SOL payload channel.
 *
 * The SDK's makeConsoleUpgrade() expects onOpen() to return an object with:
 *   - 'data'  (Buffer) events for remote output
 *   - 'exit'  ({ code }) when the session ends
 *   - 'error' (Error) on transport failure
 *   - 'close' () always after exit/error or close()
 *   - write(buf: string | Buffer): void
 *   - resize(cols, rows): void
 *   - close(): void
 *
 * SOL specifics:
 *   - activateSol(channel) returns the BMC's max chars per packet.
 *   - Writes are fire-and-forget (sendSolPacket is async but we don't await —
 *     the serialized request queue in IpmiClient handles ordering).
 *   - Unsolicited BMC→console data arrives via client.onSolData and is routed
 *     to 'data' events here.
 *   - resize() is a no-op (SOL has no window-change concept).
 */

import { EventEmitter } from 'node:events';
import type { IpmiClient } from './client/ipmiClient';

export class SolTerminalSession extends EventEmitter {
  private readonly client: IpmiClient;
  private readonly channel: number;
  private maxChars = 128;
  private closed = false;

  constructor(client: IpmiClient, channel = 1) {
    super();
    this.client = client;
    this.channel = channel;
  }

  /** Activates the SOL payload and wires up the data sink. Call once before use. */
  async open(): Promise<void> {
    try {
      this.maxChars = await this.client.activateSol(this.channel);
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      this.emit('error', err);
      this.emit('close');
      throw err;
    }

    // Route unsolicited BMC→console data to 'data' events.
    this.client.onSolData = (data: Buffer) => {
      if (!this.closed && data.length > 0) {
        this.emit('data', data);
      }
    };
  }

  /** Writes raw input bytes to the SOL channel (keyboard from the browser). */
  write(data: string | Buffer): void {
    if (this.closed) return;
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    if (buf.length === 0) return; // empty writes are pure ACKs — skip them

    // Fire-and-forget: the serialized queue in IpmiClient ensures ordering.
    // We do NOT await here because the console is interactive and blocking on
    // each keystroke would introduce unacceptable latency.
    this.client.sendSolPacket(buf, this.maxChars).catch((err) => {
      if (!this.closed) {
        const e = err instanceof Error ? err : new Error(String(err));
        this.emit('error', e);
        this.close();
      }
    });
  }

  /** SOL has no window-change concept — no-op. */
  resize(_cols: number, _rows: number): void {
    /* no-op */
  }

  /** Deactivates the SOL payload and closes the client. Idempotent. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    // Best-effort deactivate — the session may already be gone.
    this.client.deactivateSol(this.channel).catch(() => undefined);
    this.client.close();
    this.emit('close');
  }

  /** True while the SOL channel is active and not closed. */
  get connected(): boolean {
    return !this.closed;
  }
}
