// dsh-plugin conformance tests: fake Cordis ctx + fake DAP/1 hub (ws server).
// Run: npm test (offline; localhost WS only, event-driven — no sleep sync).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execSync } from 'node:child_process';
import { createRequire } from 'node:module';
import plugin, { type DapToolDef, type DshContext } from '../src/index.js';
import * as dap from '../src/crypto.js';
import { FakeHub, until, channelConfig } from './fake-hub.js';

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

test('apply() registers dap tools on the Cordis context', async () => {
  const hub = await new FakeHub().start();
  const fc = fakeCtx();
  try {
    applyTo(hub, tmpKeyPath(), fc);
    assert.deepEqual(
      fc.tools.map((t) => t.name).sort(),
      ['dap_dm', 'dap_inbox', 'dap_send', 'dap_whois'],
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
    await hub.waitFor((f) => f.op === 'hello');

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
    const msgs = (await inbox.execute({})) as InboxMsg[];
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
    await hub.waitFor((f) => f.op === 'hello');

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
    process.env.DAP_HUB_URL = prev.DAP_HUB_URL;
    process.env.DAP_KEY_PATH = prev.DAP_KEY_PATH;
    process.env.DAP_AGENT_NAME = prev.DAP_AGENT_NAME;
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
