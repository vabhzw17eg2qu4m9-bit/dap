// dsh-plugin conformance tests: fake Cordis ctx + fake DAP/1 hub (ws server).
// Run: npm test (offline; localhost WS only, event-driven — no sleep sync).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, statSync, rmSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir, hostname } from 'node:os';
import { join, dirname } from 'node:path';
import { execSync } from 'node:child_process';
import { createRequire } from 'node:module';
import plugin, { type DapToolDef, type DshContext } from '../src/index.js';
import type { DapClient } from '../src/client.js';
import * as dap from '../src/crypto.js';
import { resolveDapSettings, defaultKeyPath, DEFAULT_URL, readDapConfig, persistDapConfig } from '../src/config.js';
import { loadChannelKeys } from '../src/channels.js';
import { KeepAliveWatchdog, type KeepAlivePeer, type KaTimers } from '../src/keepalive.js';
import { FakeHub, until, channelConfig } from './fake-hub.js';

// Determinism: pin HOME (all defaults resolve under a tmp dir) and clear any
// DAP_* env leaked in from the machine running the tests.
const HOME = mkdtempSync(join(tmpdir(), 'dsh-dap-home-'));
process.env.HOME = HOME;
const DAP_ENV_KEYS = ['DAP_HUB_URL', 'DAP_KEY_PATH', 'DAP_AGENT_NAME', 'DAP_CHANNELS_FILE', 'DAP_CONFIG_FILE'];
const savedEnv = Object.fromEntries(DAP_ENV_KEYS.map((k) => [k, process.env[k]]));
for (const k of DAP_ENV_KEYS) delete process.env[k];

test.after(() => {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  rmSync(HOME, { recursive: true, force: true });
});

interface FakeCordis {
  ctx: DshContext;
  tools: DapToolDef[];
  followups: string[];
  disposeCbs: (() => void)[];
}

function fakeCtx(): FakeCordis {
  const fc: FakeCordis = {
    ctx: null as unknown as DshContext,
    tools: [],
    followups: [],
    disposeCbs: [],
  };
  fc.ctx = {
    tools: { register: (def) => void fc.tools.push(def) },
    agent: { followup: (t) => void fc.followups.push(t) },
    on: (ev, cb) => void (ev === 'dispose' && fc.disposeCbs.push(cb)),
  };
  return fc;
}

function applyTo(hub: FakeHub, keyPath: string, fc: FakeCordis): void {
  plugin.apply(fc.ctx, {
    url: hub.url,
    keyPath,
    name: 'dsh-test',
    channels: channelConfig(hub),
    backoff: { initialMs: 10, maxMs: 40 },
  });
}

function tmpKeyPath(): string {
  return join(mkdtempSync(join(tmpdir(), 'dsh-dap-')), 'identity.json');
}

/** Fresh per-test scratch dir (channels files, key paths). */
function tmpDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix + '-'));
}

const tool = (fc: { tools: DapToolDef[] }, name: string): DapToolDef => {
  const t = fc.tools.find((x) => x.name === name);
  if (!t) throw new Error('tool not registered: ' + name);
  return t;
};

test('apply() registers dap tools on the Cordis context', async () => {
  const hub = await new FakeHub().start();
  const fc = fakeCtx();
  try {
    applyTo(hub, tmpKeyPath(), fc);
    assert.deepEqual(
      fc.tools.map((t) => t.name).sort(),
      ['dap_connect', 'dap_dm', 'dap_inbox', 'dap_invite', 'dap_peers', 'dap_send', 'dap_status', 'dap_whois'],
    );
    for (const t of fc.tools) {
      const schema: Record<string, unknown> = t.inputSchema;
      assert.equal(schema.type, 'object');
    }
  } finally {
    for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
  }
});

test('dap_status: identity, link state, channels and handshake counters', async () => {
  const hub = await new FakeHub().start();
  const fc = fakeCtx();
  try {
    applyTo(hub, tmpKeyPath(), fc);
    await hub.waitFor((f) => f.op === 'flush'); // handshake done, channels joined
    const st = (await tool(fc, 'dap_status').execute({})) as Record<string, unknown>;
    assert.equal(st.connected, true);
    assert.equal(st.agentId, hub.pluginAgentId);
    assert.equal(st.name, 'dsh-test');
    assert.equal(st.url, hub.url);
    assert.deepEqual(st.channels, ['general']);
    assert.equal(st.hellos, 1, 'one connection attempt');
    assert.equal(st.welcomes, 1, 'one successful handshake');
  } finally {
    for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
  }
});

test('dap_peers: online only by default; includeOffline:true also lists a dropped agent', async () => {
  const hub = await new FakeHub().start();
  const fc = fakeCtx();
  const other = fakeCtx();
  try {
    applyTo(hub, tmpKeyPath(), fc);
    await hub.waitFor((f) => f.op === 'flush');
    const selfId = hub.pluginAgentId; // before the second client takes lastAgentId

    // Second client handshakes, then goes away for good: the hub keeps it in
    // the presence registry, marked offline.
    const clientOther = plugin.apply(other.ctx, {
      url: hub.url,
      keyPath: tmpKeyPath(),
      name: 'dsh-other',
      channels: channelConfig(hub),
      backoff: { initialMs: 10, maxMs: 40 },
    });
    await until(() => hub.hellos === 2);
    for (const cb of other.disposeCbs.splice(0)) cb(); // client.stop(): no reconnect
    await until(() => !hub.isOnline(clientOther.agentId));

    const def = tool(fc, 'dap_peers');
    const out = (await def.execute({})) as { agents: Record<string, unknown>[] };
    const wire = await hub.waitFor((f) => f.op === 'presence_query');
    assert.equal(wire.op, 'presence_query', 'asks the hub, not local cache');
    const byId = new Map(out.agents.map((a) => [String(a.agentId), a]));
    assert.ok(byId.has(selfId), 'lists itself');
    assert.ok(byId.has(hub.peerId), 'lists the fake-hub peer');
    assert.ok(!byId.has(clientOther.agentId), 'offline agent excluded by default');
    assert.ok(out.agents.every((a) => a.online === true), 'default list is online-only');
    const self = byId.get(selfId)!;
    assert.equal(self.name, 'dsh-test');
    assert.ok(Number(self.lastSeen) > 0);
    const full = (await def.execute({ includeOffline: true })) as { agents: Record<string, unknown>[] };
    const dropped = full.agents.find((a) => String(a.agentId) === clientOther.agentId);
    assert.ok(dropped, 'includeOffline:true lists the dropped agent');
    assert.equal(dropped!.online, false);
    assert.equal(dropped!.name, 'dsh-other');
  } finally {
    for (const f of [fc, other]) for (const cb of f.disposeCbs.splice(0)) cb();
    await hub.stop();
  }
});

test('hello/welcome handshake: signed hello with x25519, flush after welcome, 0600 identity reused', async () => {
  const hub = await new FakeHub().start();
  const keyPath = tmpKeyPath();
  const fc = fakeCtx();
  try {
    applyTo(hub, keyPath, fc);
    const hello = await hub.waitFor((f) => f.op === 'hello');
    assert.equal(hello.v, 1);
    assert.ok(dap.verifyFrame(hello, dap.b64d(String(hello.pubkey))), 'hello signature must verify');
    assert.equal(dap.b64d(String(hello.x25519)).length, 32, 'hello carries raw x25519 public key');
    assert.ok(typeof hello.nonce === 'string' && /^[0-9a-f]+$/.test(hello.nonce) && hello.nonce.length >= 16);
    await hub.waitFor((f) => f.op === 'flush'); // flush is sent right after welcome
    assert.equal(hub.hellos, 1);

    assert.ok(existsSync(keyPath), 'identity file created');
    assert.equal(statSync(keyPath).mode & 0o777, 0o600, 'identity file mode 0600');
  } finally {
    for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
  }

  // Same keyPath -> same identity (both keypairs stable) on a fresh hub.
  const hub2 = await new FakeHub().start();
  const fc2 = fakeCtx();
  try {
    applyTo(hub2, keyPath, fc2);
    const hello2 = await hub2.waitFor((f) => f.op === 'hello');
    const first = hub.frames.find((f) => f.op === 'hello')!;
    assert.equal(hello2.pubkey, first.pubkey, 'ed25519 identity persisted and reused');
    assert.equal(hello2.x25519, first.x25519, 'x25519 keypair persisted and reused');
  } finally {
    for (const cb of fc2.disposeCbs.splice(0)) cb();
    await hub2.stop();
    rmSync(dirname(keyPath), { recursive: true, force: true });
  }
});

test('dap_send: signed channel frame, decryptable by member, plaintext never on the wire', async () => {
  const hub = await new FakeHub().start();
  const fc = fakeCtx();
  try {
    applyTo(hub, tmpKeyPath(), fc);
    await hub.waitFor((f) => f.op === 'flush'); // welcome processed -> connected

    const send = fc.tools.find((t) => t.name === 'dap_send')!;
    await send.execute({ channel: 'general', text: 'secret payload 42' });

    const frame = await hub.waitFor((f) => f.op === 'send' && f.channel === 'general');
    assert.ok(dap.verifyFrame(frame, hub.pluginPubOrThrow), 'send frame signature must verify');
    // Member-side decrypt: channel x25519 priv x sender x25519 pub, AAD = channel.
    const text = dap.open(
      String(frame.ciphertext),
      String(frame.id),
      'general',
      hub.channel.priv,
      hub.pluginXOrThrow,
    );
    assert.equal(text, 'secret payload 42');
    assert.ok(!JSON.stringify(frame).includes('secret payload 42'), 'hub sees ciphertext only');
  } finally {
    for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
  }
});

test('inbound DM and channel msg decrypt -> Agent.followup() wake + dap_inbox', async () => {
  const hub = await new FakeHub().start();
  const fc = fakeCtx();
  try {
    applyTo(hub, tmpKeyPath(), fc);
    await hub.waitFor((f) => f.op === 'hello');

    hub.pushDm('wake up, peer here');
    await until(() => fc.followups.length > 0);
    assert.equal(fc.followups[0], `[dap:dm] ${hub.peerId}: wake up, peer here`);

    hub.pushChannel('general', 'channel hello');
    await until(() => fc.followups.length > 1);
    assert.equal(fc.followups[1], `[dap:general] ${hub.peerId}: channel hello`);

    const inbox = fc.tools.find((t) => t.name === 'dap_inbox')!;
    interface InboxMsg {
      dm: boolean;
      channel?: string;
      from: string;
      text: string;
    }
    const out = (await inbox.execute({})) as { messages: InboxMsg[]; errors: unknown[] };
    assert.deepEqual(out.errors, [], 'no hub errors in this scenario');
    const msgs = out.messages;
    assert.equal(msgs.length, 2);
    assert.equal(msgs[0].text, 'wake up, peer here');
    assert.equal(msgs[0].dm, true);
    assert.equal(msgs[1].channel, 'general');
    assert.equal(msgs[1].dm, false);

    const whois = fc.tools.find((t) => t.name === 'dap_whois')!;
    interface WhoisInfo {
      pubkey: string;
      x25519: string;
      name?: string;
    }
    const info = (await whois.execute({ agentId: hub.peerId })) as WhoisInfo;
    assert.equal(info.name, 'peer');
    assert.equal(dap.b64d(info.pubkey).length, 32);
    assert.equal(dap.b64d(info.x25519).length, 32);
  } finally {
    for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
  }
});

test('dap_dm: whois then signed DM frame the recipient can open', async () => {
  const hub = await new FakeHub().start();
  const fc = fakeCtx();
  try {
    applyTo(hub, tmpKeyPath(), fc);
    await hub.waitFor((f) => f.op === 'flush'); // welcome processed -> connected

    const dm = fc.tools.find((t) => t.name === 'dap_dm')!;
    await dm.execute({ to: hub.peerId, text: 'psst' });

    await hub.waitFor((f) => f.op === 'whois' && f.agentId === hub.peerId);
    const frame = await hub.waitFor((f) => f.op === 'send' && f.to === hub.peerId);
    assert.ok(dap.verifyFrame(frame, hub.pluginPubOrThrow));
    // Recipient side: own x25519 priv x sender x25519 pub, AAD = recipient.
    const text = dap.open(
      String(frame.ciphertext),
      String(frame.id),
      hub.peerId,
      hub.peerX.priv,
      hub.pluginXOrThrow,
    );
    assert.equal(text, 'psst');
    assert.ok(!JSON.stringify(frame).includes('psst'));
  } finally {
    for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
  }
});

test('reconnect with capped backoff after server-side drop', async () => {
  const hub = await new FakeHub().start();
  const fc = fakeCtx();
  try {
    applyTo(hub, tmpKeyPath(), fc);
    await hub.waitFor((f) => f.op === 'hello');
    await hub.waitFor((f) => f.op === 'flush');

    hub.killClient(); // drop; client re-hellos (10ms initial backoff in test config)
    await until(() => hub.hellos >= 2, 5000);
    assert.equal(hub.hellos, 2);
    // Second welcome -> flush again (mailbox drain after every welcome).
    await hub.waitFor((f) => f.op === 'flush' && hub.frames.filter((x) => x.op === 'flush').length >= 2, 5000);

    // Still functional after reconnect.
    hub.pushDm('post-reconnect');
    await until(() => fc.followups.some((t) => t.includes('post-reconnect')));
  } finally {
    for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
  }
});

test('dsh.bundle: build produces a loadable CJS bundle', () => {
  execSync('npm run build', { cwd: process.cwd(), stdio: 'pipe' });
  const bundle = join(process.cwd(), 'dist', 'dsh.bundle');
  assert.ok(existsSync(bundle), 'dist/dsh.bundle exists');
  assert.ok(statSync(bundle).size > 1000, 'bundle is non-trivial');
  interface Bundle {
    default?: { name: string; apply: unknown };
  }
  const require = createRequire(import.meta.url);
  const loaded = require(bundle) as Bundle;
  assert.equal(typeof loaded.default?.apply, 'function', 'bundle default-exports the plugin');
  assert.equal(loaded.default?.name, 'dsh-dap');
});

test('env fallbacks: DAP_HUB_URL / DAP_KEY_PATH / DAP_AGENT_NAME', async () => {
  const hub = await new FakeHub().start();
  const keyPath = tmpKeyPath();
  const prev = { ...process.env };
  process.env.DAP_HUB_URL = hub.url;
  process.env.DAP_KEY_PATH = keyPath;
  process.env.DAP_AGENT_NAME = 'env-agent';
  const fc = fakeCtx();
  try {
    plugin.apply(fc.ctx, {}); // no structured config at all
    const hello = await hub.waitFor((f) => f.op === 'hello');
    assert.equal(hello.name, 'env-agent');
    assert.ok(existsSync(keyPath));
  } finally {
    for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
    // prev[k] is undefined when the var wasn't set before — delete, don't
    // assign (assigning undefined stores the literal string "undefined").
    for (const k of ['DAP_HUB_URL', 'DAP_KEY_PATH', 'DAP_AGENT_NAME']) {
      const v = prev[k];
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});

// ---- zero-config: settings precedence, identity bootstrap, channel keys ----

test('settings precedence: config arg > DAP_* env > ~/.dap/config.json > defaults; dsh key dir + shared channels file', () => {
  try {
    // No config file, no env (cleared at the top of this file): plain defaults.
    // Identity file is derived from the agent name (hostname when unnamed),
    // under the per-adapter dsh/ key dir — two dsh agents on one machine
    // never collide; different machines get different files via hostname.
    let s = resolveDapSettings();
    assert.equal(s.url, DEFAULT_URL);
    assert.equal(s.keyPath, join(HOME, '.dap', 'keys', 'dsh', `${hostname()}.key`));
    assert.equal(s.channelsFile, join(HOME, '.dap', 'channels.json'));
    assert.equal(s.name, undefined);
    assert.equal(defaultKeyPath('bot 7'), join(HOME, '.dap', 'keys', 'dsh', 'bot_7.key'), 'name sanitized into the file name');

    // Config file fills every unset field.
    mkdirSync(join(HOME, '.dap'), { recursive: true });
    const cfgFile = join(HOME, '.dap', 'config.json');
    writeFileSync(
      cfgFile,
      JSON.stringify({ url: 'ws://cfg:1/ws', name: 'cfg-agent', keyPath: '/cfg/key.json', channelsFile: '/cfg/channels.json' }),
    );
    s = resolveDapSettings();
    assert.equal(s.url, 'ws://cfg:1/ws');
    assert.equal(s.name, 'cfg-agent');
    assert.equal(s.keyPath, '/cfg/key.json');
    assert.equal(s.channelsFile, '/cfg/channels.json');

    // Env beats the file; the file still beats the name-derived default.
    process.env.DAP_HUB_URL = 'ws://env:2/ws';
    process.env.DAP_CHANNELS_FILE = '/env/channels.json';
    process.env.DAP_AGENT_NAME = 'env-agent';
    s = resolveDapSettings();
    assert.equal(s.url, 'ws://env:2/ws');
    assert.equal(s.channelsFile, '/env/channels.json');
    assert.equal(s.name, 'env-agent');
    assert.equal(s.keyPath, '/cfg/key.json');

    // Explicit config arg beats env.
    assert.equal(resolveDapSettings({ url: 'ws://ov:3/ws' }).url, 'ws://ov:3/ws');
    assert.equal(resolveDapSettings({ keyPath: '/ov/key.json' }).keyPath, '/ov/key.json');

    // An invalid config file counts as absent; the name-derived default
    // keyPath only applies when no valid file sets one.
    writeFileSync(cfgFile, '{not json');
    delete process.env.DAP_HUB_URL;
    delete process.env.DAP_CHANNELS_FILE;
    delete process.env.DAP_AGENT_NAME;
    s = resolveDapSettings();
    assert.equal(s.url, DEFAULT_URL);
    assert.equal(s.channelsFile, join(HOME, '.dap', 'channels.json'));
    assert.equal(resolveDapSettings({ name: 'ov-agent' }).keyPath, join(HOME, '.dap', 'keys', 'dsh', 'ov-agent.key'));
  } finally {
    delete process.env.DAP_HUB_URL;
    delete process.env.DAP_CHANNELS_FILE;
    delete process.env.DAP_AGENT_NAME;
    rmSync(join(HOME, '.dap', 'config.json'), { force: true });
  }
});

test('zero-config identity: default key path ~/.dap/keys/dsh/<name>.key, auto-generated 0600', async () => {
  const hub = await new FakeHub().start();
  const fc = fakeCtx();
  try {
    plugin.apply(fc.ctx, { url: hub.url, name: 'dsh-zero' }); // nothing but a name
    const hello = await hub.waitFor((f) => f.op === 'hello');
    assert.equal(hello.name, 'dsh-zero');
    const keyPath = join(HOME, '.dap', 'keys', 'dsh', 'dsh-zero.key');
    assert.ok(existsSync(keyPath), 'identity created under the dsh key dir');
    assert.equal(statSync(keyPath).mode & 0o777, 0o600);
  } finally {
    for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
  }
});

test('auto-keygen: first send to an unknown channel keygens + persists (RMW) + joins; a second instance auto-joins from the shared file and decrypts', async () => {
  const hub = await new FakeHub().start();
  const dir = tmpDir('dsh-autokey');
  const channelsFile = join(dir, 'channels.json'); // absent: pure zero-config
  const a = fakeCtx();
  const b = fakeCtx();
  const clientA = plugin.apply(a.ctx, {
    url: hub.url, keyPath: join(dir, 'a.key'), channelsFile, backoff: { initialMs: 10, maxMs: 40 },
  });
  try {
    await hub.waitFor((f) => f.op === 'flush'); // A welcomed and connected

    // First-ever use of #general: keygen + persist + join, then the send.
    await tool(a, 'dap_send').execute({ channel: 'general', text: 'zero config' });
    const joinFrame = await hub.waitFor((f) => f.op === 'join' && f.channel === 'general');
    const saved = loadChannelKeys(channelsFile);
    assert.equal(saved.general.pub, joinFrame.chanPubkey, 'joined with the persisted pubkey');
    assert.equal(dap.b64d(saved.general.pub).length, 32, 'x25519 public key persisted');
    assert.equal(dap.b64d(saved.general.priv).length, 32, 'x25519 private key persisted');
    assert.ok(hub.channelMembers.get('general')?.has(clientA.agentId), 'creator joined');

    // A second unknown channel: read-modify-write keeps the first one.
    await tool(a, 'dap_send').execute({ channel: 'random', text: 'still zero config' });
    await hub.waitFor((f) => f.op === 'join' && f.channel === 'random');
    assert.deepEqual(Object.keys(loadChannelKeys(channelsFile)), ['general', 'random']);

    // Fresh instance, same channels file: picks the keys up with zero config
    // and auto-joins both channels after its welcome.
    const clientB = plugin.apply(b.ctx, {
      url: hub.url, keyPath: join(dir, 'b.key'), channelsFile, backoff: { initialMs: 10, maxMs: 40 },
    });
    await until(
      () =>
        hub.channelMembers.get('general')?.has(clientB.agentId) === true &&
        hub.channelMembers.get('random')?.has(clientB.agentId) === true,
    );

    // B decrypts A's later channel send (hub routes to joined members).
    await tool(a, 'dap_send').execute({ channel: 'general', text: 'second message' });
    await until(() => b.followups.some((t) => t.includes('second message')));
    const wake = b.followups.find((t) => t.includes('second message'))!;
    assert.match(wake, new RegExp(`\\[dap:general\\] ${clientA.agentId}: second message`));
    assert.ok(!JSON.stringify(hub.frames).includes('second message'), 'hub sees ciphertext only');
  } finally {
    for (const fc of [a, b]) for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('invite: A dap_invites B over E2E DM; B persists + joins + notice (not inbox); post-invite channel send decrypts', async () => {
  const hub = await new FakeHub().start();
  const dir = tmpDir('dsh-invite');
  const fileA = join(dir, 'a-channels.json');
  const fileB = join(dir, 'b-channels.json');
  writeFileSync(fileB, '{}'); // B literally starts with an empty channels file
  const a = fakeCtx();
  const b = fakeCtx();
  const clientA = plugin.apply(a.ctx, {
    url: hub.url, keyPath: join(dir, 'a.key'), channelsFile: fileA, name: 'alice', backoff: { initialMs: 10, maxMs: 40 },
  });
  const clientB = plugin.apply(b.ctx, {
    url: hub.url, keyPath: join(dir, 'b.key'), channelsFile: fileB, name: 'bob', backoff: { initialMs: 10, maxMs: 40 },
  });
  try {
    await until(() => hub.hellos >= 2); // both welcomed
    assert.equal(Object.keys(loadChannelKeys(fileB)).length, 0, 'B holds no channel keys yet');

    // dap_invite on a channel A doesn't hold yet: zero-config creation inlined.
    await tool(a, 'dap_invite').execute({ channel: 'general', to: clientB.agentId });
    const dmFrame = await hub.waitFor((f) => f.op === 'send' && f.to === clientB.agentId);
    assert.ok(!String(dmFrame.ciphertext).includes('chankey'), 'hub never sees the invite plaintext');
    const creatorKeys = loadChannelKeys(fileA);
    assert.ok(creatorKeys.general?.pub, 'creator keypair persisted');
    assert.ok(hub.channelMembers.get('general')?.has(clientA.agentId), 'A created + joined #general');

    // B processes the invite DM: persist + join + followup notice, no inbox.
    await until(() => hub.channelMembers.get('general')?.has(clientB.agentId) === true);
    await until(() => b.followups.some((t) => t.includes(`invited to #general by ${clientA.agentId}`)));
    const inboxOut = (await tool(b, 'dap_inbox').execute({})) as { messages: unknown[]; errors: unknown[] };
    assert.equal(inboxOut.messages.length, 0, 'chankey DM is not chat: no inbox entry');
    assert.equal(loadChannelKeys(fileB).general?.pub, creatorKeys.general?.pub, 'B persisted the invited keypair');

    // Post-invite: B decrypts A's channel send with the invited key.
    await tool(a, 'dap_send').execute({ channel: 'general', text: 'welcome aboard' });
    await until(() => b.followups.some((t) => t.includes('welcome aboard')));
    assert.match(b.followups.find((t) => t.includes('welcome aboard'))!, /\[dap:general\]/);
    assert.ok(!JSON.stringify(hub.frames).includes('welcome aboard'), 'hub sees ciphertext only');
  } finally {
    for (const fc of [a, b]) for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('canonical JSON matches wire form: undefined keys dropped, keys sorted, no HTML escaping', () => {
  assert.equal(dap.canonicalJson({ b: 1, a: undefined, c: [2, undefined] }), '{"b":1,"c":[2,null]}');
  assert.equal(dap.canonicalJson({ s: '<>&' }), '{"s":"<>&"}');
  const signed = { op: 'hello', ts: 7, name: undefined };
  // After a JSON round-trip (undefined name dropped) the canonical form is identical,
  // so a signature made pre-send verifies post-parse.
  assert.equal(dap.canonicalJson(JSON.parse(JSON.stringify(signed))), dap.canonicalJson(signed));
});

// ---- keepalive / honest failure / error surfacing (client resilience) ----

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

test('honest failure: dap_send/dap_dm while disconnected return not-connected', async () => {
  const fc = fakeCtx();
  // Unreachable hub: the client can never complete a welcome, so every
  // tool call must fail honestly instead of reporting a delivered frame.
  plugin.apply(fc.ctx, {
    url: 'ws://127.0.0.1:1/ws',
    keyPath: tmpKeyPath(),
    backoff: { initialMs: 10, maxMs: 40 },
  });
  try {
    const send = fc.tools.find((t) => t.name === 'dap_send')!;
    const dm = fc.tools.find((t) => t.name === 'dap_dm')!;
    const sendOut = (await send.execute({ channel: 'general', text: 'anyone?' })) as { ok: boolean; error?: string };
    assert.equal(sendOut.ok, false);
    assert.match(String(sendOut.error), /not connected/);
    const dmOut = (await dm.execute({ to: 'a_0123456789abcdef', text: 'anyone?' })) as { ok: boolean; error?: string };
    assert.equal(dmOut.ok, false);
    assert.match(String(dmOut.error), /not connected/);
  } finally {
    for (const cb of fc.disposeCbs.splice(0)) cb();
  }
});

test('error surfacing: hub error frame -> followup notice + dap_inbox errors', async () => {
  const hub = await new FakeHub().start();
  const fc = fakeCtx();
  try {
    applyTo(hub, tmpKeyPath(), fc);
    await hub.waitFor((f) => f.op === 'hello');

    hub.send({ op: 'error', code: 'access_denied', msg: 'channel key mismatch' });
    await until(() => fc.followups.some((t) => t.includes('access_denied')));
    assert.match(fc.followups.find((t) => t.includes('access_denied'))!, /hub rejected a frame — access_denied: channel key mismatch/);

    const inbox = fc.tools.find((t) => t.name === 'dap_inbox')!;
    const out = (await inbox.execute({})) as { messages: unknown[]; errors: Array<{ code: string; msg: string }> };
    assert.equal(out.errors.length, 1);
    assert.equal(out.errors[0].code, 'access_denied');
    assert.equal(out.errors[0].msg, 'channel key mismatch');
    // Drain is destructive — a second call sees no repeats.
    const again = (await inbox.execute({})) as { errors: unknown[] };
    assert.deepEqual(again.errors, []);
  } finally {
    for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
  }
});

test('dap_connect: retargets to a second hub (bare host), new identity, default room, persisted config', async () => {
  const hub1 = await new FakeHub().start();
  const hub2 = await new FakeHub().start();
  const dir = tmpDir('dsh-connect');
  const cfgFile = join(dir, 'config.json');
  const fc = fakeCtx();
  process.env.DAP_CONFIG_FILE = cfgFile;
  const client = plugin.apply(fc.ctx, {
    url: hub1.url,
    keyPath: join(dir, 'a.key'),
    channelsFile: join(dir, 'channels.json'),
    backoff: { initialMs: 10, maxMs: 40 },
  });
  try {
    await hub1.waitFor((f) => f.op === 'flush'); // welcomed on hub1
    const oldId = client.agentId;
    assert.equal(hub1.pluginAgentId, oldId);

    // Bare host form: scheme and hub path implied by normalization.
    const r = (await tool(fc, 'dap_connect').execute({
      host: hub2.url.replace(/^ws:\/\//, ''),
      name: 'renamed',
      channel: 'lobby',
    })) as { ok: boolean; url: string; name: string; agentId: string; channels: string[] };
    assert.equal(r.ok, true);
    assert.equal(r.url, hub2.url, 'bare host normalized to the full ws URL');
    assert.equal(r.name, 'renamed');
    assert.notEqual(r.agentId, oldId, 'new name => new identity');
    assert.ok(r.channels.includes('lobby'), 'default room ensured');

    // The second welcome lands on hub2 — exactly one connection attempt there
    // (the retired hub1 socket must not arm a phantom reconnect).
    await hub2.waitFor((f) => f.op === 'flush');
    assert.equal(client.welcomes, 2, 'welcome count 2 across the retarget');
    assert.equal(hub2.hellos, 1, 'no stray duplicate connection to hub2');
    assert.equal(hub2.pluginAgentId, client.agentId, 'hub2 knows the new identity');
    await until(() => hub2.channelMembers.get('lobby')?.has(client.agentId) === true);
    await until(() => !hub1.isOnline(oldId), 5000);

    // Name-derived identity under the dsh key dir, auto-generated 0600.
    const keyFile = join(HOME, '.dap', 'keys', 'dsh', 'renamed.key');
    assert.ok(existsSync(keyFile), 'identity created under ~/.dap/keys/dsh/');
    assert.equal(statSync(keyFile).mode & 0o777, 0o600);

    // Config merged into the injected path (url/name/default room).
    const cfg = JSON.parse(readFileSync(cfgFile, 'utf8')) as Record<string, unknown>;
    assert.equal(cfg.url, hub2.url);
    assert.equal(cfg.name, 'renamed');
    assert.deepEqual(cfg.channels, ['lobby']);

    // The blind-join caveat must ride in the tool description.
    const desc = tool(fc, 'dap_connect').description;
    assert.match(desc, /dap_invite you/);
    assert.match(desc, /members cannot read you/);
  } finally {
    delete process.env.DAP_CONFIG_FILE;
    for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub1.stop();
    await hub2.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- pending by-name invites (arm + poller + restart redelivery) ----

test('dap_invite <unknown name>: arms a pending invite (default channel, connect line), auto-creates + joins the channel, persists deduped', async () => {
  const hub = await new FakeHub().start();
  const dir = tmpDir('dsh-arm');
  const cfgFile = join(dir, 'config.json');
  const chFile = join(dir, 'a-channels.json');
  process.env.DAP_CONFIG_FILE = cfgFile;
  const fc = fakeCtx();
  const client = plugin.apply(fc.ctx, {
    url: hub.url, keyPath: join(dir, 'a.key'), channelsFile: chFile, name: 'inviter',
    invitePollMs: 3_600_000, backoff: { initialMs: 10, maxMs: 40 }, // the tick never fires here
  });
  try {
    await hub.waitFor((f) => f.op === 'flush'); // welcomed
    const host = hub.url.replace(/^ws:\/\//, '').replace(/\/ws$/, '');

    const r = (await tool(fc, 'dap_invite').execute({ to: 'carol' })) as {
      ok: boolean; pending: boolean; name: string; channel: string; connectLine: string;
    };
    assert.equal(r.ok, true);
    assert.equal(r.pending, true);
    assert.equal(r.name, 'carol');
    assert.equal(r.channel, 'general', 'channel defaults to general');
    assert.equal(r.connectLine, `send to carol:  /dap ${host} carol`, 'paste-ready connect line');

    // Arm-time channel creation: keygen + join under the INVITER's key.
    await hub.waitFor((f) => f.op === 'join' && f.channel === 'general');
    assert.ok(hub.channelMembers.get('general')?.has(client.agentId), 'inviter joined at arm time');
    assert.ok(loadChannelKeys(chFile).general?.priv, 'channel keypair persisted under the inviter key');
    assert.deepEqual(readDapConfig(cfgFile).invites, [{ name: 'carol', channel: 'general' }], 'pending persisted');

    // Same (name, channel) again, different case: deduped, still one entry.
    await tool(fc, 'dap_invite').execute({ to: 'CAROL' });
    assert.deepEqual(readDapConfig(cfgFile).invites, [{ name: 'carol', channel: 'general' }], 'deduped');

    // A different channel arms a second entry and creates that channel too.
    const r2 = (await tool(fc, 'dap_invite').execute({ to: 'carol', channel: 'team' })) as { channel: string };
    assert.equal(r2.channel, 'team');
    await hub.waitFor((f) => f.op === 'join' && f.channel === 'team');
    assert.deepEqual(readDapConfig(cfgFile).invites, [
      { name: 'carol', channel: 'general' },
      { name: 'carol', channel: 'team' },
    ], 'both pendings persisted');
  } finally {
    delete process.env.DAP_CONFIG_FILE;
    for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('pending invite: invitee connects later under the armed name -> poller tick DMs the chankey, invitee joins, pending removed', async () => {
  const hub = await new FakeHub().start();
  const dir = tmpDir('dsh-poll');
  const cfgFile = join(dir, 'config.json');
  const fileA = join(dir, 'a-channels.json');
  const fileB = join(dir, 'b-channels.json');
  writeFileSync(fileB, '{}');
  process.env.DAP_CONFIG_FILE = cfgFile;
  const a = fakeCtx();
  const b = fakeCtx();
  const clientA = plugin.apply(a.ctx, {
    url: hub.url, keyPath: join(dir, 'a.key'), channelsFile: fileA, name: 'inviter',
    invitePollMs: 25, backoff: { initialMs: 10, maxMs: 40 },
  });
  let clientB: DapClient | undefined;
  try {
    await hub.waitFor((f) => f.op === 'flush');
    await tool(a, 'dap_invite').execute({ to: 'carol' }); // carol not on the hub yet: armed
    assert.equal((readDapConfig(cfgFile).invites ?? []).length, 1);

    // The invitee is a different user: she must not load the inviter's config.
    delete process.env.DAP_CONFIG_FILE;
    clientB = plugin.apply(b.ctx, {
      url: hub.url, keyPath: join(dir, 'b.key'), channelsFile: fileB, name: 'carol',
      invitePollMs: 3_600_000, backoff: { initialMs: 10, maxMs: 40 },
    });
    await until(() => clientB?.connected === true);

    // Poller tick: presence now sees carol online -> automatic chankey DM.
    const dmFrame = await hub.waitFor((f) => f.op === 'send' && f.to === clientB!.agentId);
    assert.ok(!String(dmFrame.ciphertext).includes('chankey'), 'hub never sees the invite plaintext');
    await until(() => hub.channelMembers.get('general')?.has(clientB!.agentId) === true);
    await until(() => (readDapConfig(cfgFile).invites ?? []).length === 0, 5000);
    await until(() => a.followups.some((t) => t.includes('[dap] invited carol to #general')));
    assert.ok(b.followups.some((t) => t.includes(`invited to #general by ${clientA.agentId}`)), 'invitee noticed the invite');
    assert.equal(loadChannelKeys(fileB).general?.pub, loadChannelKeys(fileA).general?.pub, 'same channel key delivered');
  } finally {
    delete process.env.DAP_CONFIG_FILE;
    for (const fc of [a, b]) for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('dap_invite <online name>: immediate chankey DM, nothing armed in config', async () => {
  const hub = await new FakeHub().start();
  const dir = tmpDir('dsh-online');
  const cfgFile = join(dir, 'config.json');
  const fileA = join(dir, 'a-channels.json');
  const fileB = join(dir, 'b-channels.json');
  writeFileSync(fileB, '{}');
  process.env.DAP_CONFIG_FILE = cfgFile;
  const a = fakeCtx();
  const b = fakeCtx();
  const clientA = plugin.apply(a.ctx, {
    url: hub.url, keyPath: join(dir, 'a.key'), channelsFile: fileA, name: 'alice',
    invitePollMs: 3_600_000, backoff: { initialMs: 10, maxMs: 40 },
  });
  const clientB = plugin.apply(b.ctx, {
    url: hub.url, keyPath: join(dir, 'b.key'), channelsFile: fileB, name: 'bob',
    invitePollMs: 3_600_000, backoff: { initialMs: 10, maxMs: 40 },
  });
  try {
    await until(() => clientA.connected && clientB.connected);
    await tool(a, 'dap_invite').execute({ to: 'bob' }); // online name: straight to the chankey DM
    const dmFrame = await hub.waitFor((f) => f.op === 'send' && f.to === clientB.agentId);
    assert.ok(!String(dmFrame.ciphertext).includes('chankey'), 'hub never sees the invite plaintext');
    await until(() => hub.channelMembers.get('general')?.has(clientB.agentId) === true);
    assert.ok(b.followups.some((t) => t.includes(`invited to #general by ${clientA.agentId}`)), 'invitee noticed the invite');
    assert.deepEqual(readDapConfig(cfgFile).invites, [], 'online name: nothing armed');
  } finally {
    delete process.env.DAP_CONFIG_FILE;
    for (const fc of [a, b]) for (const cb of fc.disposeCbs.splice(0)) cb();
    await hub.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('pending invites survive a restart: welcome-time check delivers without waiting a tick', async () => {
  const hub = await new FakeHub().start();
  const dir = tmpDir('dsh-restart');
  const cfgFile = join(dir, 'config.json');
  const fileA = join(dir, 'a-channels.json');
  const fileB = join(dir, 'b-channels.json');
  writeFileSync(fileB, '{}');
  process.env.DAP_CONFIG_FILE = cfgFile;
  const a1 = fakeCtx();
  const a2 = fakeCtx();
  const b = fakeCtx();
  plugin.apply(a1.ctx, {
    url: hub.url, keyPath: join(dir, 'a1.key'), channelsFile: fileA, name: 'inviter',
    invitePollMs: 3_600_000, backoff: { initialMs: 10, maxMs: 40 }, // no tick: only welcome checks run
  });
  let clientA2: DapClient | undefined;
  let clientB: DapClient | undefined;
  try {
    await hub.waitFor((f) => f.op === 'flush');
    await tool(a1, 'dap_invite').execute({ to: 'carol' });
    // The arm-time delivery check settles (its presence pass finds no carol).
    await until(() => hub.frames.filter((f) => f.op === 'presence_query').length >= 2);
    for (const cb of a1.disposeCbs.splice(0)) cb(); // inviter goes away entirely

    delete process.env.DAP_CONFIG_FILE; // the invitee never loads the inviter's pendings
    clientB = plugin.apply(b.ctx, {
      url: hub.url, keyPath: join(dir, 'b.key'), channelsFile: fileB, name: 'carol',
      invitePollMs: 3_600_000, backoff: { initialMs: 10, maxMs: 40 },
    });
    await until(() => clientB?.connected === true);
    process.env.DAP_CONFIG_FILE = cfgFile;

    // Fresh inviter instance, same config + channels file: the welcome-time
    // check delivers carol's invite without waiting for a poller tick.
    clientA2 = plugin.apply(a2.ctx, {
      url: hub.url, keyPath: join(dir, 'a2.key'), channelsFile: fileA, name: 'inviter2',
      invitePollMs: 3_600_000, backoff: { initialMs: 10, maxMs: 40 },
    });
    await until(() => hub.channelMembers.get('general')?.has(clientB!.agentId) === true);
    assert.equal(loadChannelKeys(fileB).general?.pub, loadChannelKeys(fileA).general?.pub, 'same channel key delivered');
    await until(() => (readDapConfig(cfgFile).invites ?? []).length === 0, 5000);
    assert.ok(a2.followups.some((t) => t.includes('[dap] invited carol to #general')), 'inviter notified');
  } finally {
    delete process.env.DAP_CONFIG_FILE;
    for (const fc of [a2, b]) for (const cb of fc.disposeCbs.splice(0)) cb(); // a1 already disposed
    await hub.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('config invites back-compat: missing key defaults to [], non-array treated as absent, persist keeps other keys', () => {
  const dir = tmpDir('dsh-cfginv');
  const cfgFile = join(dir, 'config.json');
  try {
    writeFileSync(cfgFile, JSON.stringify({ url: 'ws://legacy:9/ws', name: 'legacy', channels: ['ops'] }));
    const cfg = readDapConfig(cfgFile);
    assert.deepEqual(cfg.invites, [], 'missing invites key defaults to []');
    assert.equal(cfg.url, 'ws://legacy:9/ws');
    persistDapConfig({ invites: [{ name: 'newbie', channel: 'general' }] }, cfgFile);
    const after = readDapConfig(cfgFile);
    assert.deepEqual(after.invites, [{ name: 'newbie', channel: 'general' }]);
    assert.equal(after.url, 'ws://legacy:9/ws', 'existing keys survive');
    assert.deepEqual(after.channels, ['ops']);
    writeFileSync(cfgFile, JSON.stringify({ invites: 'corrupt' }));
    assert.deepEqual(readDapConfig(cfgFile).invites, [], 'non-array invites treated as absent');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
