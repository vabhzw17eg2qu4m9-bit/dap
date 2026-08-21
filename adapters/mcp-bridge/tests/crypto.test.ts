// Unit tests for the DAP/1 codec + crypto: canonical JSON (wire form),
// signature payload, Ed25519 sign/verify, agentId derivation, X25519+HKDF+
// ChaCha20-Poly1305 seal/open round-trip.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as dap from '../src/crypto.js';

test('canonicalJson: keys sorted recursively, no whitespace, undefined dropped, no HTML escaping', () => {
  const frame = { ts: 1, op: 'send', sig: 'x', channel: undefined, nested: { b: 1, a: '<>&' } };
  assert.equal(dap.canonicalJson(frame), '{"nested":{"a":"<>&","b":1},"op":"send","ts":1}');
});

test('sigPayload = dap1|op|ts|hex(sha256(canonicalJSON(frame)))', () => {
  const frame = { op: 'hello', ts: 1700000000000, v: 1 };
  const payload = dap.sigPayload(frame);
  const digest = createHash('sha256').update(dap.canonicalJson(frame)).digest('hex');
  assert.equal(payload, `dap1|hello|1700000000000|${digest}`);
});

test('signFrame / verifyFrame round-trip; tampering breaks it', () => {
  const kp = dap.newEdKeypair();
  const frame = { op: 'send', id: 'u1', ts: Date.now(), ciphertext: 'AAA' };
  frame.sig = dap.signFrame(frame, kp.priv);
  assert.equal(dap.verifyFrame(frame, kp.pub), true);
  const tampered = { ...frame, ts: frame.ts + 1 };
  assert.equal(dap.verifyFrame(tampered, kp.pub), false);
  const other = dap.newEdKeypair();
  assert.equal(dap.verifyFrame(frame, other.pub), false);
});

test('agentIdOf: hex(sha256(pub))[:16], stable', () => {
  const kp = dap.newEdKeypair();
  const id = dap.agentIdOf(kp.pub);
  assert.match(id, /^[0-9a-f]{16}$/);
  assert.equal(id, dap.agentIdOf(kp.pub));
});

test('E2E round-trip: X25519 ECDH + HKDF + ChaCha20-Poly1305 between two agents', () => {
  const alice = dap.newX25519Keypair();
  const bob = dap.newX25519Keypair();
  const frameId = '9af0e7c2-0000-4000-8000-000000000000';
  const text = 'end-to-end round-trip <plaintext> ünïcode';
  const ct = dap.seal(text, frameId, 'a_bob', alice.priv, bob.pub);
  // Same secret from Bob's side: own priv x sender pub.
  assert.equal(dap.open(ct, frameId, 'a_bob', bob.priv, alice.pub), text);
  assert.notEqual(ct, text);
});

test('open fails on wrong key, wrong AAD, wrong frame id', () => {
  const alice = dap.newX25519Keypair();
  const bob = dap.newX25519Keypair();
  const mallory = dap.newX25519Keypair();
  const ct = dap.seal('secret', 'id1', 'a_bob', alice.priv, bob.pub);
  assert.throws(() => dap.open(ct, 'id1', 'a_bob', mallory.priv, alice.pub));
  assert.throws(() => dap.open(ct, 'id1', 'a_wrong', bob.priv, alice.pub));
  assert.throws(() => dap.open(ct, 'id2', 'a_bob', bob.priv, alice.pub));
});
