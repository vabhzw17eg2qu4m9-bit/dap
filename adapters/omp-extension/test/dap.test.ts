import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import dapExtension from '../src/index.ts';
import { agentIdFor, b64, canonicalJSON, loadOrCreateKeys, unb64 } from '../src/crypto.ts';
import { resolveDapSettings } from '../src/config.ts';
import { loadChannelKeys, newChannelKeypair } from '../src/channels.ts';
import type { DapClient, MsgFrame, Timers } from '../src/conn.ts';
import type { ExtensionAPI, SendMessageOptions, SessionCtx, ToolDefinition } from '../src/types.ts';
import { FakeHub } from './fake-hub.ts';

const KEYDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'dap-omp-test-'));
let keySeq = 0;
const nextKeyPath = (): string => path.join(KEYDIR, 'key-' + ++keySeq + '.json');

// Determinism: pin HOME (defaults resolve under KEYDIR) and clear any DAP_*
// env leaked in from the machine running the tests.
process.env.HOME = KEYDIR;
const DAP_ENV_KEYS = ['DAP_HUB_URL', 'DAP_KEY_PATH', 'DAP_AGENT_NAME', 'DAP_CHANNELS_FILE'];
const savedEnv = Object.fromEntries(DAP_ENV_KEYS.map((k) => [k, process.env[k]]));
for (const k of DAP_ENV_KEYS) delete process.env[k];

test.after(() => {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  fs.rmSync(KEYDIR, { recursive: true, force: true });
});

/** Wait for the next emission of `event` after this call — race-free. */
function nextEvent<T>(client: DapClient, event: string): Promise<T> {
  return client.waitForAfter<T>(event, client.eventCount(event));
}

interface Captured {
  ctx: ExtensionAPI;
  tools: Map<string, ToolDefinition>;
  sent: { msg: string; opts: SendMessageOptions | undefined }[];
  entries: { type: string; data: unknown }[];
  labels: string[];
  fire(event: string, sctx: SessionCtx): void;
}

/** Fake ExtensionAPI matching the real omp surface exactly. */
function fakeCtx(): Captured {
  const tools = new Map<string, ToolDefinition>();
  const sent: Captured['sent'] = [];
  const entries: Captured['entries'] = [];
  const labels: string[] = [];
  const handlers = new Map<string, (event: unknown, ctx: SessionCtx) => void | Promise<void>>();
  const ctx: ExtensionAPI = {
    registerTool: (tool) => void tools.set(tool.name, tool),
    sendMessage: (msg, opts) => void sent.push({ msg, opts }),
    appendEntry: (type, data) => void entries.push({ type, data }),
    setLabel: (label) => void labels.push(label),
    on: (event, handler) => void handlers.set(event, handler),
  };
  return {
    ctx,
    tools,
    sent,
    entries,
    labels,
    fire: (event, sctx) => void handlers.get(event)?.(event, sctx),
  };
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

const tool = (c: Captured, name: string): ToolDefinition => {
  const t = c.tools.get(name);
  assert.ok(t, 'tool not registered: ' + name);
  return t;
};

/** Invoke a registered tool the way omp does: execute(toolCallId, params);
 *  returns the details field of the AgentToolResult. */
const run = async <T>(c: Captured, name: string, params: Record<string, unknown> = {}): Promise<T> =>
  (await tool(c, name).execute('test-call-id', params)).details as T;

const lastEntry = <T>(c: Captured): T => c.entries.at(-1)!.data as T;

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
  const chan = newChannelKeypair();
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channels: { general: chan.pub } });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelPrivs: { general: chan.priv } });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');
    const text = 'check ignition and may god’s love be with you';

    const inbound = nextEvent<MsgFrame>(extB.client, 'inbound');
    const result = await run<{ ok: boolean; id: string }>(a, 'dap_send', { channel: 'general', text });
    assert.equal(result.ok, true);
    const raw = await inbound;

    assert.equal(hub.verifiedSends.length, 1, 'hub verified the Ed25519 send signature');
    assert.notEqual(raw.ciphertext, Buffer.from(text).toString('base64'));
    assert.ok(!JSON.stringify(hub.verifiedSends).includes(text), 'plaintext never reaches the hub');

    assert.equal(b.sent.length, 1, 'inbound msg steered into the turn');
    assert.match(b.sent[0].msg, /#general/);
    assert.match(b.sent[0].msg, new RegExp(text));
    assert.equal(b.sent[0].opts?.deliverAs, 'steer');
    assert.equal(b.sent[0].opts?.triggerTurn, true, 'triggerTurn wakes an idle agent');
    assert.equal(b.entries.at(-1)!.type, 'io.dap.message', 'namespaced durable entry');
    const entry = lastEntry<{ text: string; channel: string }>(b);
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

    const inboundB = nextEvent<MsgFrame>(extB.client, 'inbound');
    await run(a, 'dap_dm', { to: extB.client.agentId, text: 'psst, ping' });
    await inboundB;
    assert.equal(b.sent.length, 1);
    assert.match(b.sent[0].msg, /DM/);
    assert.match(b.sent[0].msg, /psst, ping/);
    const dmEntry = lastEntry<{ dm: boolean; text: string }>(b);
    assert.equal(dmEntry.dm, true);
    assert.equal(dmEntry.text, 'psst, ping');
    assert.equal(hub.verifiedSends[0]?.to, extB.client.agentId, 'DM delivered to the recipient only');

    const inboundA = nextEvent(extA.client, 'inbound');
    await run(b, 'dap_dm', { to: extA.client.agentId, text: 'pong' });
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

    await run(a, 'dap_dm', { to: bId, text: 'while you were out (1)' });
    await run(a, 'dap_dm', { to: bId, text: 'while you were out (2)' });
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

      const inbox = await run<{
        count: number;
        entries: { text: string; dm: boolean; from: string }[];
      }>(b2, 'dap_inbox', { limit: 10 });
      assert.equal(inbox.count, 2);
      assert.deepEqual(
        inbox.entries.map((e) => e.text),
        ['while you were out (2)', 'while you were out (1)'],
        'latest first',
      );
      assert.ok(inbox.entries.every((e) => e.dm && e.from === extA.client.agentId));

      const info = await run<{
        online: boolean;
        pubkey: string;
        x25519: string;
      }>(b2, 'dap_whois', { agentId: extA.client.agentId });
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

test('settings precedence: override > env > ~/.dap/config.json > defaults; channelsFile default ~/.dap/channels.json', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dap-omp-cfg-'));
  const prevHome = process.env.HOME;
  process.env.HOME = home;
  try {
    // No config file, no env: plain defaults. Identity file is derived from
    // the agent name (hostname when unnamed) — two agents on one machine
    // never collide, and it is auto-generated on first use.
    let s = resolveDapSettings();
    assert.equal(s.url, 'ws://127.0.0.1:8787/ws');
    assert.equal(s.keyPath, path.join(home, '.dap', 'keys', `${os.hostname()}.key`));
    assert.equal(s.channelsFile, path.join(home, '.dap', 'channels.json'));
    assert.equal(s.name, undefined);

    // Config file fills every unset field.
    fs.mkdirSync(path.join(home, '.dap'), { recursive: true });
    const cfgFile = path.join(home, '.dap', 'config.json');
    fs.writeFileSync(
      cfgFile,
      JSON.stringify({ url: 'ws://cfg:1/ws', name: 'cfg-agent', keyPath: '/cfg/key.json', channelsFile: '/cfg/channels.json' }),
    );
    s = resolveDapSettings();
    assert.equal(s.url, 'ws://cfg:1/ws');
    assert.equal(s.name, 'cfg-agent');
    assert.equal(s.keyPath, '/cfg/key.json');
    assert.equal(s.channelsFile, '/cfg/channels.json');

    // Env beats the file; the file still beats the defaults.
    process.env.DAP_HUB_URL = 'ws://env:2/ws';
    process.env.DAP_CHANNELS_FILE = '/env/channels.json';
    s = resolveDapSettings();
    assert.equal(s.url, 'ws://env:2/ws');
    assert.equal(s.channelsFile, '/env/channels.json');
    assert.equal(s.keyPath, '/cfg/key.json', 'file beats default when env is silent');

    // Explicit override beats env.
    assert.equal(resolveDapSettings({ url: 'ws://ov:3/ws' }).url, 'ws://ov:3/ws');

    // An invalid config file counts as absent.
    fs.writeFileSync(cfgFile, '{not json');
    delete process.env.DAP_HUB_URL;
    delete process.env.DAP_CHANNELS_FILE;
    s = resolveDapSettings();
    assert.equal(s.url, 'ws://127.0.0.1:8787/ws');
    assert.equal(s.channelsFile, path.join(home, '.dap', 'channels.json'));
  } finally {
    process.env.HOME = prevHome;
    delete process.env.DAP_HUB_URL;
    delete process.env.DAP_CHANNELS_FILE;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('auto-keygen: send to an unknown channel persists keys; a second instance joins and decrypts', async () => {
  const hub = await new FakeHub().listen();
  const channelsFile = path.join(KEYDIR, 'auto-keygen-' + ++keySeq + '.json');
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile });
  try {
    await nextEvent(extA.client, 'welcome');

    // First-ever use of #general: keygen + persist + join, then the send works.
    const joinedGeneral = nextEvent<{ channel: string }>(extA.client, 'joined');
    const result = await run<{ ok: boolean }>(a, 'dap_send', { channel: 'general', text: 'zero config' });
    assert.equal(result.ok, true);
    assert.equal((await joinedGeneral).channel, 'general');
    // A second unknown channel: read-modify-write keeps the first one.
    const joinedRandom = nextEvent<{ channel: string }>(extA.client, 'joined');
    await run(a, 'dap_send', { channel: 'random', text: 'still zero config' });
    assert.equal((await joinedRandom).channel, 'random');
    const saved = loadChannelKeys(channelsFile);
    assert.deepEqual(Object.keys(saved), ['general', 'random']);
    assert.equal(unb64(saved.general.pub).length, 32, 'x25519 public key persisted');
    assert.equal(unb64(saved.general.priv).length, 32, 'x25519 private key persisted');
    assert.ok(hub.channelMembers.get('general')?.has(extA.client.agentId), 'creator joined');

    // Fresh factory, same channels file: picks the keys up with zero config.
    const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile });
    try {
      await nextEvent(extB.client, 'welcome');
      await nextEvent(extB.client, 'joined'); // auto-joined #general + #random from the file
      assert.ok(hub.channelMembers.get('general')?.has(extB.client.agentId));

      const inbound = nextEvent<MsgFrame>(extB.client, 'inbound');
      await run(a, 'dap_send', { channel: 'general', text: 'second message' });
      await inbound;
      assert.equal(b.sent.length, 1, 'B decrypted the channel message');
      assert.match(b.sent[0].msg, /#general/);
      assert.match(b.sent[0].msg, /second message/);
    } finally {
      extB.dispose();
    }
  } finally {
    extA.dispose();
    await hub.close();
  }
});

test('invite: A auto-creates #general, dap_invite DMs the chankey to B; B joins and decrypts later sends', async () => {
  const hub = await new FakeHub().listen();
  const fileA = path.join(KEYDIR, 'invite-a-' + ++keySeq + '.json');
  const fileB = path.join(KEYDIR, 'invite-b-' + ++keySeq + '.json');
  fs.writeFileSync(fileB, '{}'); // B literally starts with an empty channels file
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileA, name: 'alice' });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileB, name: 'bob' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');
    assert.equal(Object.keys(loadChannelKeys(fileB)).length, 0, 'B holds no channel keys yet');

    // dap_invite on a channel A doesn't hold yet: zero-config creation inlined.
    const joinedA = nextEvent<{ channel: string }>(extA.client, 'joined');
    const invite = await run<{ ok: boolean }>(a, 'dap_invite', { channel: 'general', to: extB.client.agentId });
    assert.equal(invite.ok, true);
    assert.equal((await joinedA).channel, 'general', 'A created + joined #general');
    assert.ok(loadChannelKeys(fileA).general?.pub, 'creator keypair persisted');
    await nextEvent(extB.client, 'inbound'); // invite DM fully processed (deterministic)
    await nextEvent(extB.client, 'joined');

    assert.equal(b.sent.length, 1, 'one steer so far: the invite notice');
    assert.ok(
      b.sent[0].msg.includes('[dap] invited to #general by ' + extA.client.agentId),
      'notice text: ' + b.sent[0].msg,
    );
    assert.equal(b.sent[0].opts?.deliverAs, 'steer');
    assert.equal(b.entries.length, 0, 'chankey DM is not chat: no inbox entry');
    assert.equal(
      loadChannelKeys(fileB).general?.pub,
      loadChannelKeys(fileA).general?.pub,
      'B persisted the invited keypair',
    );
    assert.ok(hub.channelMembers.get('general')?.has(extB.client.agentId), 'B joined after the invite');

    // The actual payload the hub routed was ciphertext-wrapped JSON over E2E DM.
    const dmSend = hub.verifiedSends.find((f) => f.to === extB.client.agentId);
    assert.ok(dmSend && !dmSend.ciphertext.includes('chankey'), 'hub never sees the invite plaintext');

    const inbound = nextEvent<MsgFrame>(extB.client, 'inbound');
    await run(a, 'dap_send', { channel: 'general', text: 'welcome aboard' });
    await inbound;
    assert.match(b.sent.at(-1)!.msg, /#general/);
    assert.match(b.sent.at(-1)!.msg, /welcome aboard/);
  } finally {
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('idle agent: inbound wakes it via steer+triggerTurn; session_start notifies when hasUI', async () => {
  const hub = await new FakeHub().listen();
  const chan = newChannelKeypair();
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channels: { general: chan.pub }, name: 'alice' });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelPrivs: { general: chan.priv }, name: 'bob' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');

    // Visible liveness: label set at load, notify on session_start when a UI exists.
    assert.deepEqual(b.labels, ['DAP — distributed agents']);
    const notifications: string[] = [];
    const timers = { setInterval: (): number => 0, clearTimer: (): void => {} };
    b.fire('session_start', {
      ui: { notify: (text: string) => void notifications.push(text) },
      hasUI: true,
      isIdle: () => true,
      ...timers,
    });
    assert.equal(notifications.length, 1);
    assert.ok(
      notifications[0] === `DAP connected as ${extB.client.agentId} (bob)`,
      'notify text: ' + notifications[0],
    );
    // Headless session: the hasUI guard suppresses the notify, no crash.
    b.fire('session_start', { hasUI: false, isIdle: () => false, ...timers });
    assert.equal(notifications.length, 1);

    // Inbound while idle: steer + triggerTurn — without it an idle agent shows nothing.
    const inbound = nextEvent<MsgFrame>(extB.client, 'inbound');
    await run(a, 'dap_send', { channel: 'general', text: 'wake up' });
    await inbound;
    assert.equal(b.sent.length, 1);
    assert.deepEqual(b.sent[0].opts, { deliverAs: 'steer', triggerTurn: true });
    assert.equal(b.entries.at(-1)!.type, 'io.dap.message');
  } finally {
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('hub error frames surface to the session — steer + durable entry, never silent', async () => {
  const hub = await new FakeHub().listen();
  const cap = fakeCtx();
  const ext = dapExtension(cap.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'a' });
  try {
    await nextEvent(ext.client, 'welcome');
    const rejected = nextEvent(ext.client, 'error');
    hub.sendError(ext.client.agentId, 'unknown_agent', 'no such agent: deadbeef');
    await rejected;
    assert.ok(cap.sent.some((s) => s.msg.includes('unknown_agent')), 'steer mentions the code');
    assert.deepEqual(
      cap.sent.find((s) => s.msg.includes('unknown_agent'))!.opts,
      { deliverAs: 'steer', triggerTurn: true },
    );
    assert.equal(cap.entries.at(-1)!.type, 'io.dap.error');
  } finally {
    ext.dispose();
    await hub.close();
  }
});

test('tools fail honestly while disconnected: ok:false instead of a silent drop', async () => {
  const cap = fakeCtx();
  const ext = dapExtension(cap.ctx, {
    url: 'ws://127.0.0.1:9/ws', // nothing listens: connection down
    keyPath: nextKeyPath(),
    name: 'x',
    channels: { general: 'A'.repeat(43) + '=' }, // explicit keys: no file writes
    backoff: { initial: 60_000, max: 60_000 }, // no reconnect storm during the test
  });
  try {
    const r = await run<{ ok: boolean; error: string }>(cap, 'dap_send', {
      channel: 'general',
      text: 'must not claim success',
    });
    assert.equal(r.ok, false);
    assert.match(r.error, /not connected/);
    const dm = await run<{ ok: boolean }>(cap, 'dap_dm', { to: 'deadbeef', text: 'x' });
    assert.equal(dm.ok, false);
  } finally {
    ext.dispose();
  }
});
