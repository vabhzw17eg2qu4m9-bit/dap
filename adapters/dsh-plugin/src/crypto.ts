// DAP/1 crypto: canonical JSON, Ed25519 signing, X25519 ECDH + HKDF-SHA256 +
// ChaCha20-Poly1305 payload sealing. Pure functions only — spec: docs/protocol.md.
// Addendum: agents carry a dedicated X25519 keypair (hello field "x25519") for
// E2E; Ed25519 stays identity-only. Canonical JSON never HTML-escapes (JS
// JSON.stringify doesn't — matches the Go hub's SetEscapeHTML(false)).
import { randomBytes } from 'node:crypto';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

export type Frame = Record<string, unknown>;
export type Bytes = Uint8Array;

export const utf8 = (s: string): Bytes => new TextEncoder().encode(s);
export const b64e = (b: Bytes): string => Buffer.from(b).toString('base64');
export const b64d = (s: string): Bytes => new Uint8Array(Buffer.from(s, 'base64'));

/** Canonical JSON: keys sorted recursively, no whitespace. Keys with undefined
 * values are dropped (JSON.stringify semantics) so the signer's canonical form
 * of a frame equals the verifier's form of the parsed frame. `sig` is excluded
 * for the same reason (spec: frameWithoutSigField). */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).filter((k) => k !== 'sig' && o[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`;
}

export const sha256Hex = (b: Bytes): string => Buffer.from(sha256(b)).toString('hex');
export const agentIdOf = (pubRaw: Bytes): string => sha256Hex(pubRaw).slice(0, 16);

/** sigPayload = "dap1|" + op + "|" + ts + "|" + hex(sha256(canonicalJSON(frame))) */
export function sigPayload(frame: Frame): string {
  return `dap1|${frame.op}|${frame.ts}|${sha256Hex(utf8(canonicalJson(frame)))}`;
}

export function signFrame(frame: Frame, priv: Bytes): string {
  return b64e(ed25519.sign(utf8(sigPayload(frame)), priv));
}

export function verifyFrame(frame: Frame, pub: Bytes): boolean {
  if (typeof frame.sig !== 'string') return false;
  return ed25519.verify(b64d(frame.sig), utf8(sigPayload(frame)), pub);
}

export const newEdKeypair = (): { priv: Bytes; pub: Bytes } => {
  const priv = ed25519.utils.randomSecretKey();
  return { priv, pub: ed25519.getPublicKey(priv) };
};

/** Channel / agent E2E keypairs are plain X25519. */
export const newX25519Keypair = (): { priv: Bytes; pub: Bytes } => {
  const kp = x25519.keygen();
  return { priv: kp.secretKey, pub: kp.publicKey };
};

/** Key = HKDF-SHA256(ikm = ecdh_secret, salt = frame_id, info = "dap1/v1") */
function deriveKey(secret: Bytes, frameId: string): Bytes {
  return hkdf(sha256, secret, utf8(frameId), utf8('dap1/v1'), 32);
}

/** AAD = "dap1|" + frame_id + "|" + (channel or recipient agentId) */
const aadOf = (frameId: string, peer: string): Bytes => utf8(`dap1|${frameId}|${peer}`);

/** ciphertext = base64( nonce(12) || ct || tag(16) ); tag is appended by the AEAD. */
export function seal(plaintext: string, frameId: string, peer: string, xPriv: Bytes, peerXPub: Bytes): string {
  const key = deriveKey(x25519.getSharedSecret(xPriv, peerXPub), frameId);
  const nonce = randomBytes(12);
  const ct = chacha20poly1305(key, nonce, aadOf(frameId, peer)).encrypt(utf8(plaintext));
  return b64e(new Uint8Array([...nonce, ...ct]));
}

/** Inverse of seal; throws if the AEAD tag does not verify. */
export function open(ciphertextB64: string, frameId: string, peer: string, xPriv: Bytes, peerXPub: Bytes): string {
  const raw = b64d(ciphertextB64);
  const key = deriveKey(x25519.getSharedSecret(xPriv, peerXPub), frameId);
  const pt = chacha20poly1305(key, raw.slice(0, 12), aadOf(frameId, peer)).decrypt(raw.slice(12));
  return new TextDecoder().decode(pt);
}
