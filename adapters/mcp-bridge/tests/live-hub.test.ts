// LIVE round-trip through the REAL hub (built from ../../hub, spawned on an
// ephemeral localhost port): TWO bridge client instances with separate key
// files. A creates the channel (first join registers its chanPubkey), B gets
// the channel keys out-of-band and joins, A sends E2E — B decrypts and A gets
// the sender echo; then one DM exchange A→B with whois-first.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DapClient, type MsgEvent } from '../src/client.js';
import { startHub } from './hub.js';
import { pollUntil } from './util.js';

function collect(client: DapClient): { all: () => MsgEvent[]; has: (pred: (m: MsgEvent) => boolean) => boolean } {
  const got: MsgEvent[] = [];
  client.onMessage((m) => got.push(m));
  return { all: () => [...got], has: (pred) => got.some(pred) };
}

test('live hub round-trip: channel create/join + E2E fanout + sender echo + DM (whois first)', async () => {
  const hub = await startHub();
  const keyA = join(mkdtempSync(join(tmpdir(), 'dap-live-a-')), 'a.key');
  const keyB = join(mkdtempSync(join(tmpdir(), 'dap-live-b-')), 'b.key');
  const A = new DapClient({ url: hub.url, keyPath: keyA, name: 'live-a' });
  const B = new DapClient({ url: hub.url, keyPath: keyB, name: 'live-b' });
  const seenA = collect(A);
  const seenB = collect(B);

  A.start();
  B.start();
  await Promise.all([A.ready(), B.ready()]);

  // Identity files: 0600 per spec.
  assert.equal(statSync(keyA).mode & 0o777, 0o600);
  assert.equal(statSync(keyB).mode & 0o777, 0o600);

  // A joins first → creates the channel and registers its chanPubkey.
  const chan = await A.ensureChannel('live');
  assert.equal(chan.created, true);
  assert.match(chan.pub, /^[A-Za-z0-9+/]{43}=$/);
  // Out-of-band key distribution: B receives the channel keypair and joins.
  B.addChannel({ name: 'live', pub: chan.pub, priv: chan.priv });
  await B.join('live', chan.pub);

  const text = 'e2e round-trip through the live hub';
  const sent = await A.send('live', text);
  assert.equal(sent.ok, true);
  assert.equal(sent.created, undefined); // channel existed already

  // B receives and decrypts; A gets the sender echo of its own message.
  await pollUntil(() => seenB.has((m) => m.channel === 'live' && m.text === text));
  await pollUntil(() => seenA.has((m) => m.channel === 'live' && m.text === text));
  const atB = seenB.all().find((m) => m.channel === 'live')!;
  assert.equal(atB.from, A.agentId);
  assert.equal(atB.dm, false);
  const echoAtA = seenA.all().find((m) => m.channel === 'live')!;
  assert.equal(echoAtA.text, text);

  // DM: whois runs first (A needs B's x25519 for key agreement).
  const whoisBefore = A.whoisCalls;
  const dmText = 'direct message round-trip';
  await A.dm(B.agentId, dmText);
  assert.equal(A.whoisCalls, whoisBefore + 1);
  await pollUntil(() => seenB.has((m) => m.dm && m.text === dmText));
  const dmAtB = seenB.all().find((m) => m.dm)!;
  assert.equal(dmAtB.from, A.agentId);
  // Spec: DMs give the sender no echo.
  assert.equal(seenA.all().some((m) => m.dm), false);

  A.stop();
  B.stop();
  const exit = await hub.stop();
  assert.ok(exit.signal === 'SIGTERM' || exit.code !== null, 'hub process reaped on teardown');
});
