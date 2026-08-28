// Audit-pinned failure paths: undecryptable inbound frames surface in the
// error ring (the drain dap_inbox serves — never silent), and hub calls in
// flight across a retarget fail fast with 'retargeted' instead of drifting
// to the 5s waiter timeout. Stub-WS convention (keepalive.test.ts): pure
// event waits, zero real timeouts.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocketServer, type WebSocket } from 'ws';
import { DapClient, type HubErrorEvent } from '../src/client.js';
import { b64e, utf8 } from '../src/crypto.js';

const tmpKey = (): string => join(mkdtempSync(join(tmpdir(), 'dap-stale-')), 'agent.key');

/** Event wait with a failure-only deadline: crisp red (never a hang) when
 *  the surfaced event never comes; the timer is cleared on success. */
async function raceDeadline(event: Promise<HubErrorEvent>, failMsg: string): Promise<HubErrorEvent> {
  let deadline: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      event,
      new Promise<never>((_, reject) => {
        deadline = setTimeout(() => reject(new Error(failMsg)), 2000);
      }),
    ]);
  } finally {
    clearTimeout(deadline);
  }
}

/** Minimal hub stand-in: welcome the hello, answer whois with a peer that
 *  has a (wrong) x25519 key, and optionally push one inbound frame. */
async function stubHub(handle: (ws: WebSocket) => void): Promise<{ url: string; close(): Promise<void> }> {
  const wss = new WebSocketServer({ port: 0 });
  const { promise: listening, resolve: onListening } = Promise.withResolvers<void>();
  wss.on('connection', (ws) => {
    ws.on('message', (data) => {
      const frame = JSON.parse(String(data)) as Record<string, unknown>;
      if (frame.op === 'hello') {
        ws.send(JSON.stringify({ op: 'welcome' }));
        handle(ws);
      } else if (frame.op === 'whois') {
        ws.send(JSON.stringify({
          op: 'agent_info',
          agentId: frame.agentId,
          pubkey: b64e(utf8('peer-pubkey')),
          x25519: b64e(utf8('0123456789abcdef0123456789abcdef')), // 32 bytes, but not the real key
          online: true,
        }));
      }
    });
  });
  wss.once('listening', onListening);
  await listening;
  const addr = wss.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    url: `ws://127.0.0.1:${port}/ws`,
    close: () => {
      const { promise, resolve: onClosed } = Promise.withResolvers<void>();
      wss.close(() => onClosed());
      return promise;
    },
  };
}

test('undecryptable inbound DM surfaces in the error ring (dap_inbox drain), never silent', async () => {
  const SENDER = 'a_badfeed00000001';
  const hub = await stubHub((ws) => {
    // Inbound DM with garbage ciphertext right after the handshake: the
    // client must whois the sender, fail the AEAD open, and still surface.
    ws.send(JSON.stringify({
      op: 'msg',
      id: 'frame-undecryptable-1',
      from: SENDER,
      to: 'a_thisbridge00000',
      ts: Date.now(),
      ciphertext: b64e(utf8('not a real ciphertext — tag can never verify')),
    }));
  });
  const { promise: surfaced, resolve: gotSurfaced } = Promise.withResolvers<HubErrorEvent>();
  const dap = new DapClient({ url: hub.url, keyPath: tmpKey(), onHubError: (e) => gotSurfaced(e) });
  try {
    dap.start();
    const event = await raceDeadline(
      surfaced,
      'undecryptable msg was silently dropped — never surfaced to the error ring',
    );
    assert.equal(event.code, 'undecryptable');
    assert.match(event.msg, /undecryptable msg/);
    assert.equal(event.from, SENDER, 'sender frame field carried on the entry');
    assert.equal(event.id, 'frame-undecryptable-1', 'frame id carried on the entry');
    assert.deepEqual(dap.drainErrors(), [event], 'ring and hook carry the same event');
    assert.deepEqual(dap.drainErrors(), [], 'drain is destructive — no repeats');
    assert.deepEqual(dap.drainInbox(), [], 'garbage never lands in the inbox as chat text');
  } finally {
    dap.stop();
    await hub.close();
  }
});

test('dm() in flight across a retarget fails fast with retargeted (never the 5s timeout)', async () => {
  const PEER = 'a_0123456789abcdef';
  const hub = await stubHub(() => {}); // answers hello + whois: but for the retarget the dm would proceed
  const dap = new DapClient({ url: hub.url, keyPath: tmpKey() });
  try {
    dap.start();
    await dap.ready(); // welcomed on the stub hub
    const pending = dap.dm(PEER, 'hello?'); // whois parked — stub's reply cannot beat this sync block
    dap.retarget({ url: 'ws://127.0.0.1:1/ws' }); // dead target: dying socket must not strand the waiter
    await assert.rejects(pending, /retargeted/, 'fail-fast rejection, not the timeout-whois drift');
  } finally {
    dap.stop(); // also clears the reconnect timer the dead retarget armed
    await hub.close();
  }
});
