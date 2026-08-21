import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { x25519 } from '@noble/curves/ed25519';
import dapExtension from '../src/index.ts';
import { agentIdFor, b64, canonicalJSON, loadOrCreateKeys } from '../src/crypto.ts';
import type { DapClient, MsgFrame, Timers } from '../src/conn.ts';
import type { ExtensionAPI, ToolDefinition } from '../src/types.ts';
import { FakeHub } from './fake-hub.ts';

const KEYDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'dap-omp-test-'));
let keySeq = 0;
const nextKeyPath = (): string => path.join(KEYDIR, 'key-' + ++keySeq + '.json');

test.after(() => fs.rmSync(KEYDIR, { recursive: true, force: true }));

/** Wait for the next emission of `event` after this call — race-free. */
function nextEvent<T>(client: DapClient, event: string): Promise<T> {
  return client.waitForAfter<T>(event, client.eventCount(event));
}

interface Captured {
  ctx: ExtensionAPI;
  tools: Map<string, ToolDefinition>;
  sent: { msg: string; opts: { type?: string } | undefined }[];
  entries: unknown[];
}

function fakeCtx(): Captured {
  const tools = new Map<string, ToolDefinition>();
  const sent: Captured['sent'] = [];
  const entries: unknown[] = [];
  const ctx: ExtensionAPI = {
    registerTool: (tool) => void tools.set(tool.name, tool),
    sendMessage: (msg, opts) => void sent.push({ msg, opts }),
    appendEntry: (entry) => void entries.push(entry),
  };
  return { ctx, tools, sent, entries };
}

/** Deterministic stand-in for setInterval: tests fire due callbacks manually. */
class ManualTimers {
  private readonly tasks = new Map<number, () => void>();
  private next = 1;
  readonly timers: Timers = {
    setInterval: (fn) => {
      const id = this.next++;
      this.tasks.set(id, fn);
      return id;
    },
    clearInterval: (h) => void this.tasks.delete(h as number),
  };
  fireAll(): void {
    for (const fn of [...this.tasks.values()]) fn();
  }
}

function channelKeypair(): { pub: string; priv: string } {
  const priv = x25519.utils.randomPrivateKey();
  return { pub: b64(x25519.getPublicKey(priv)), priv: b64(priv) };
}

const tool = (c: Captured, name: string): ToolDefinition => {
  const t = c.tools.get(name);
  assert.ok(t, 'tool not registered: ' + name);
  return t;
};

test('canonicalJSON: sorted keys, no whitespace, no HTML escaping (Go SetEscapeHTML(false) parity)', () => {
  assert.equal(canonicalJSON({ b: 1, a: [{ z: true, y: null }] }), '{"a":[{"y":null,"z":true}],"b":1}');
  assert.equal(canonicalJSON({ s: '<&>»' }), '{"s":"<&>»"}', 'no \\u003c-style escaping');
});

test('hello handshake: signed hello -> welcome, key file created 0600', async () => {
  const hub = await new FakeHub().listen();
  const keyPath = nextKeyPath();
  const cap = fakeCtx();
  const ext = dapExtension(cap.ctx, { url: hub.url, keyPath, name: 'tester <&>' });
  try {
    const welcome = await nextEvent<{ agentId: string }>(ext.client, 'welcome');

    const keys = loadOrCreateKeys(keyPath);
    const expectedId = agentIdFor(keys.pub);
    assert.equal(welcome.agentId, expectedId);
    assert.equal(ext.client.agentId, expectedId);
    assert.ok(ext.client.resumeToken.length >= 16);
    assert.ok(hub.agents.has(expectedId), 'hub registered the agent');
    assert.ok(hub.log.includes('hello-verified:' + expectedId), 'hub verified the signature');
    assert.equal(fs.statSync(keyPath).mode & 0o777, 0o600, 'key file mode 0600');
  } finally {
    ext.dispose();
    await hub.close();
  }
});

test('signed channel send accepted; E2E fan-out, hub sees ciphertext only', async () => {
  const hub = await new FakeHub().listen();
  const chan = channelKeypair();
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channels: { general: chan.pub } });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelPrivs: { general: chan.priv } });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');
    const text = 'check ignition and may god’s love be with you';

    const inbound = nextEvent<MsgFrame>(extB.client, 'inbound');
    const result = await tool(a, 'dap_send').execute({ channel: 'general', text });
    assert.equal((result as { ok: boolean }).ok, true);
    const raw = await inbound;

    assert.equal(hub.verifiedSends.length, 1, 'hub verified the Ed25519 send signature');
    assert.notEqual(raw.ciphertext, Buffer.from(text).toString('base64'));
    assert.ok(!JSON.stringify(hub.verifiedSends).includes(text), 'plaintext never reaches the hub');

    assert.equal(b.sent.length, 1, 'inbound msg steered into the turn');
    assert.match(b.sent[0].msg, /#general/);
    assert.match(b.sent[0].msg, new RegExp(text));
    assert.equal(b.sent[0].opts?.type, 'steer');
    const entry = b.entries.at(-1) as { text: string; channel: string };
    assert.equal(entry.text, text);
    assert.equal(entry.channel, 'general');
  } finally {
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('DM decrypt round-trip between two client instances (both directions)', async () => {
  const hub = await new FakeHub().listen();
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'alice' });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'bob' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');

    const inboundB = nextEvent(extB.client, 'inbound');
    await tool(a, 'dap_dm').execute({ to: extB.client.agentId, text: 'psst, ping' });
    await inboundB;
    assert.equal(b.sent.length, 1);
    assert.match(b.sent[0].msg, /DM/);
    assert.match(b.sent[0].msg, /psst, ping/);
    const dmEntry = b.entries.at(-1) as { dm: boolean; text: string };
    assert.equal(dmEntry.dm, true);
    assert.equal(dmEntry.text, 'psst, ping');
    assert.equal(hub.verifiedSends[0]?.to, extB.client.agentId, 'DM delivered to the recipient only');

    const inboundA = nextEvent(extA.client, 'inbound');
    await tool(b, 'dap_dm').execute({ to: extA.client.agentId, text: 'pong' });
    await inboundA;
    assert.match(a.sent[0].msg, /pong/);
  } finally {
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('hub rejects a send frame with a bad signature', async () => {
  const hub = await new FakeHub().listen();
  const cap = fakeCtx();
  const ext = dapExtension(cap.ctx, { url: hub.url, keyPath: nextKeyPath() });
  try {
    await nextEvent(ext.client, 'welcome');
    const gotError = nextEvent<{ code: string }>(ext.client, 'error');
    ext.client.send({
      op: 'send',
      channel: 'general',
      id: crypto.randomUUID(),
      ts: Date.now(),
      ciphertext: Buffer.from('forged').toString('base64'),
      sig: Buffer.from('not-a-signature').toString('base64'),
    });
    const err = await gotError;
    assert.equal(err.code, 'bad_signature');
    assert.deepEqual(hub.rejected, [{ code: 'bad_signature', agentId: ext.client.agentId }]);
    assert.equal(hub.verifiedSends.length, 0);
  } finally {
    ext.dispose();
    await hub.close();
  }
});

test('reconnect after server drop: setInterval loop, backoff reset on welcome', async () => {
  const hub = await new FakeHub().listen();
  const cap = fakeCtx();
  const clock = new ManualTimers();
  const ext = dapExtension(cap.ctx, { url: hub.url, keyPath: nextKeyPath(), timers: clock.timers });
  try {
    await nextEvent(ext.client, 'welcome');
    assert.equal(ext.client.helloCount, 1);

    const closed = nextEvent(ext.client, 'close');
    hub.drop(ext.client.agentId);
    await closed;
    assert.deepEqual(ext.client.backoffSchedule, [1000], 'first retry scheduled at 1s');

    const welcomed = nextEvent(ext.client, 'welcome');
    clock.fireAll();
    await welcomed;
    assert.equal(ext.client.helloCount, 2, 'hello re-sent on reconnect');
    assert.equal(ext.client.welcomeCount, 2);
    assert.equal(
      hub.log.filter((l) => l === 'hello-verified:' + ext.client.agentId).length,
      2,
      'hub verified both hellos',
    );

    const closedAgain = nextEvent(ext.client, 'close');
    hub.drop(ext.client.agentId);
    await closedAgain;
    assert.deepEqual(ext.client.backoffSchedule, [1000, 1000], 'backoff reset after successful welcome');
  } finally {
    ext.dispose();
    await hub.close();
  }
});

test('backoff doubles 1s..30s cap against a dead endpoint (no real sleeps)', async () => {
  const cap = fakeCtx();
  const clock = new ManualTimers();
  const ext = dapExtension(cap.ctx, { url: 'ws://127.0.0.1:9/ws', keyPath: nextKeyPath(), timers: clock.timers });
  try {
    await nextEvent(ext.client, 'close'); // initial attempt: connection refused
    for (let i = 0; i < 7; i++) {
      const closed = nextEvent(ext.client, 'close');
      clock.fireAll();
      await closed;
    }
    assert.deepEqual(ext.client.backoffSchedule, [1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
  } finally {
    ext.dispose();
  }
});

test('offline mailbox: flush after welcome -> steer + durable inbox; inbox/whois tools', async () => {
  const hub = await new FakeHub().listen();
  const a = fakeCtx();
  const aKeyPath = nextKeyPath();
  const bKeyPath = nextKeyPath();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: aKeyPath });
  try {
    await nextEvent(extA.client, 'welcome');
    const bKeys = loadOrCreateKeys(bKeyPath);
    const bId = agentIdFor(bKeys.pub);

    // B was online, then went offline -> its bounded mailbox starts queuing.
    const b1 = dapExtension(fakeCtx().ctx, { url: hub.url, keyPath: bKeyPath });
    await nextEvent(b1.client, 'welcome');
    b1.dispose();
    await hub.waitOffline(bId);

    await tool(a, 'dap_dm').execute({ to: bId, text: 'while you were out (1)' });
    await tool(a, 'dap_dm').execute({ to: bId, text: 'while you were out (2)' });
    await hub.waitVerifiedSends(2);
    assert.equal(hub.mailboxes.get(bId)?.length, 2);
    assert.ok(!JSON.stringify(hub.mailboxes).includes('while you were out'), 'mailbox holds ciphertext only');

    const b2 = fakeCtx();
    const extB = dapExtension(b2.ctx, { url: hub.url, keyPath: bKeyPath });
    try {
      const flushed = await nextEvent<{ count: number }>(extB.client, 'flushed');
      assert.equal(flushed.count, 2, 'mailbox drained in order');
      await extB.client.waitForAfter('inbound', extB.client.eventCount('inbound') + 1);
      assert.equal(b2.sent.length, 2, 'both messages steered in');
      assert.match(b2.sent[0].msg, /while you were out \(1\)/, 'delivered in mailbox order');
      assert.match(b2.sent[1].msg, /while you were out \(2\)/);
      assert.equal(b2.entries.length, 2, 'appendEntry persisted both');

      const inbox = (await tool(b2, 'dap_inbox').execute({ limit: 10 })) as {
        count: number;
        entries: { text: string; dm: boolean; from: string }[];
      };
      assert.equal(inbox.count, 2);
      assert.deepEqual(
        inbox.entries.map((e) => e.text),
        ['while you were out (2)', 'while you were out (1)'],
        'latest first',
      );
      assert.ok(inbox.entries.every((e) => e.dm && e.from === extA.client.agentId));

      const info = (await tool(b2, 'dap_whois').execute({ agentId: extA.client.agentId })) as {
        online: boolean;
        pubkey: string;
        x25519: string;
      };
      assert.equal(info.online, true);
      assert.equal(info.pubkey, b64(loadOrCreateKeys(aKeyPath).pub));
      assert.equal(info.x25519, b64(loadOrCreateKeys(aKeyPath).xpub), 'agent_info echoes the x25519 pub');
    } finally {
      extB.dispose();
    }
  } finally {
    extA.dispose();
    await hub.close();
  }
});
