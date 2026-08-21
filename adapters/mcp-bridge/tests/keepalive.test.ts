// Client resilience: keepalive watchdog (manual timers — zero real waits),
// honest failure (send/dm while disconnected), hub error-frame surfacing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WebSocketServer } from 'ws';
import { KeepAliveWatchdog, type KeepAlivePeer, type KaTimers } from '../src/keepalive.js';
import { DapClient, type HubErrorEvent } from '../src/client.js';

/** Fully manual timers: tests drive time, zero real waits. */
class ManualKaTimers {
  private seq = 0;
  private intervals = new Map<number, () => void>();
  private timeouts = new Map<number, () => void>();
  readonly timers: KaTimers = {
    setInterval: (fn) => {
      const id = ++this.seq;
      this.intervals.set(id, fn);
      return id;
    },
    clearInterval: (h) => void this.intervals.delete(h as number),
    setTimeout: (fn) => {
      const id = ++this.seq;
      this.timeouts.set(id, fn);
      return id;
    },
    clearTimeout: (h) => void this.timeouts.delete(h as number),
  };
  tickInterval(): void {
    for (const fn of [...this.intervals.values()]) fn();
  }
  elapseDeadlines(): void {
    for (const fn of [...this.timeouts.values()]) fn();
  }
  get pending(): number {
    return this.timeouts.size;
  }
}

/** Synchronous peer: pong (if it answers) fires DURING ping() — the hardest
 *  ordering case (deadline must be armed before ping). */
function stubPeer(answers: boolean): KeepAlivePeer & { pings: number; killed: boolean } {
  const peer = {
    pings: 0,
    killed: false,
    pongCb: undefined as (() => void) | undefined,
    ping() {
      peer.pings++;
      if (answers) peer.pongCb?.();
    },
    terminate() {
      peer.killed = true;
    },
    on(_event: 'pong', listener: () => void) {
      peer.pongCb = listener;
      return peer;
    },
  };
  return peer;
}

const tmpKey = (): string => join(mkdtempSync(join(tmpdir(), 'dap-ka-')), 'agent.key');

test('watchdog terminates a silent peer once the pong deadline elapses', () => {
  const peer = stubPeer(false); // half-open: pings out, no pong back
  const mt = new ManualKaTimers();
  const wd = new KeepAliveWatchdog({ every: 20, pongDeadline: 50 }, mt.timers);
  wd.start(peer);
  assert.ok(peer.pings >= 1, 'start pings immediately');
  assert.equal(mt.pending, 1, 'one deadline armed');
  mt.elapseDeadlines();
  assert.equal(peer.killed, true, 'dead conn is terminated');
  assert.equal(wd.terminated, true);
});

test('watchdog never terminates a peer that answers pings (sync pong ordering)', () => {
  const peer = stubPeer(true);
  const mt = new ManualKaTimers();
  const wd = new KeepAliveWatchdog({ every: 20, pongDeadline: 50 }, mt.timers);
  wd.start(peer);
  mt.tickInterval();
  mt.tickInterval();
  assert.equal(wd.pingsSent, 3, 'start + two cycles');
  assert.equal(mt.pending, 0, 'every pong cleared its deadline');
  assert.equal(peer.killed, false);
  mt.elapseDeadlines(); // nothing armed — must stay a no-op
  assert.equal(peer.killed, false);
});

test('stopped watchdog clears pending deadlines and never terminates', () => {
  const peer = stubPeer(false);
  const mt = new ManualKaTimers();
  const wd = new KeepAliveWatchdog({ every: 20, pongDeadline: 50 }, mt.timers);
  wd.start(peer);
  assert.equal(mt.pending, 1);
  wd.stop();
  assert.equal(mt.pending, 0, 'deadline disarmed');
  mt.elapseDeadlines();
  assert.equal(peer.killed, false);
});

test('watchdog re-arms on a fresh peer after terminating a dead one', () => {
  const dead = stubPeer(false);
  const mt = new ManualKaTimers();
  const wd = new KeepAliveWatchdog({ every: 20, pongDeadline: 50 }, mt.timers);
  wd.start(dead);
  mt.elapseDeadlines();
  assert.equal(dead.killed, true);
  // Reconnect: same watchdog instance, new socket — must watch again.
  const fresh = stubPeer(false);
  wd.start(fresh);
  assert.equal(fresh.pings, 1, 'fresh peer is pinged immediately');
  mt.elapseDeadlines();
  assert.equal(fresh.killed, true, 'fresh silent peer also gets terminated');
});

test('honest failure: send/dm while disconnected reject with not-connected', async () => {
  const dap = new DapClient({ url: 'ws://127.0.0.1:1/ws', keyPath: tmpKey() }); // never started
  assert.equal(dap.connected, false);
  await assert.rejects(dap.send('general', 'hello?'), /not connected/);
  await assert.rejects(dap.dm('a_0123456789abcdef', 'hello?'), /not connected/);
});

test('error surfacing: hub error frame fires onHubError and lands in drainErrors', async () => {
  const wss = new WebSocketServer({ port: 0 });
  const { promise: listening, resolve: onListening } = Promise.withResolvers<void>();
  wss.on('connection', (ws) => {
    ws.on('message', () => {
      // Answer the hello with a hub-style rejection (access_denied).
      ws.send(JSON.stringify({ op: 'error', code: 'access_denied', msg: 'channel key mismatch' }));
    });
  });
  wss.once('listening', onListening);
  await listening;
  const addr = wss.address();
  const { promise: sawError, resolve: gotError } = Promise.withResolvers<HubErrorEvent>();
  const dap = new DapClient({
    url: `ws://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}/ws`,
    keyPath: tmpKey(),
    onHubError: (e) => gotError(e),
  });
  try {
    dap.start();
    const event = await sawError; // pure event wait — no timers
    assert.equal(event.code, 'access_denied');
    assert.equal(event.msg, 'channel key mismatch');
    assert.deepEqual(dap.drainErrors(), [event], 'ring and hook carry the same event');
    assert.deepEqual(dap.drainErrors(), [], 'drain is destructive — no repeats');
  } finally {
    dap.stop();
    const { promise: closed, resolve: onClosed } = Promise.withResolvers<void>();
    wss.close(() => onClosed());
    await closed;
  }
});
