package main

// crypto_test.go — auth gauntlet (Ed25519 signatures, ts window, nonce
// replay) and the DAP/1 E2E envelope (X25519 + HKDF-SHA256 +
// ChaCha20-Poly1305) proving the hub routes opaque ciphertext.

import (
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/chacha20poly1305"
)

func expectErrCode(t *testing.T, c *websocket.Conn, code string, skip ...string) {
	t.Helper()
	f := readUntil(t, c, "error", skip...)
	if f.Code != code {
		t.Fatalf("error code %q, want %q", f.Code, code)
	}
}

// newX25519Pair generates a dedicated X25519 keypair for E2E key
// agreement (never derived from, or reused with, the ed25519 key).
func newX25519Pair(t *testing.T) (*ecdh.PrivateKey, string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
}

func withE2E(t *testing.T, a *testAgent) *testAgent {
	t.Helper()
	a.e2ePriv, a.e2ePubB64 = newX25519Pair(t)
	return a
}

func pubFromB64(t *testing.T, b64 string) *ecdh.PublicKey {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// e2eKey derives the payload key: HKDF-SHA256(ikm = x25519 ECDH secret,
// salt = frame_id, info = "dap1/v1") → 32 bytes (spec §Crypto).
func e2eKey(t *testing.T, priv *ecdh.PrivateKey, peer *ecdh.PublicKey, frameID string) []byte {
	t.Helper()
	secret, err := priv.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hkdf.Key(sha256.New, secret, []byte(frameID), "dap1/v1", chacha20poly1305.KeySize)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// seal encrypts to base64(nonce(12) || ct || tag(16)) with the DAP/1 AAD.
func seal(t *testing.T, priv *ecdh.PrivateKey, peer *ecdh.PublicKey, frameID, aad, plaintext string) string {
	t.Helper()
	aead, err := chacha20poly1305.New(e2eKey(t, priv, peer, frameID))
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	rand.Read(nonce)
	ct := aead.Seal(nil, nonce, []byte(plaintext), []byte(aad))
	return base64.StdEncoding.EncodeToString(append(nonce, ct...))
}

func unseal(t *testing.T, priv *ecdh.PrivateKey, peer *ecdh.PublicKey, frameID, aad, ciphertext string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.New(e2eKey(t, priv, peer, frameID))
	if err != nil {
		t.Fatal(err)
	}
	ns := chacha20poly1305.NonceSize
	pt, err := aead.Open(nil, raw[:ns], raw[ns:], []byte(aad))
	if err != nil {
		t.Fatal(err)
	}
	return string(pt)
}

func TestHelloBadSignature(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, attacker := newAgent(t, "a"), newAgent(t, "attacker")
	c := dial(t, srv)
	writeSigned(t, c, attacker.priv, helloMap(a)) // signed by the wrong key
	expectErrCode(t, c, codeBadSig)
}

func TestHelloMissingSig(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	c := dial(t, srv)
	writeJSONFrame(t, c, helloMap(a))
	expectErrCode(t, c, codeBadSig)
}

func TestHelloBadPubkey(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	c := dial(t, srv)
	m := helloMap(a)
	m["pubkey"] = "!!!not-base64!!!"
	writeSigned(t, c, a.priv, m)
	expectErrCode(t, c, codeBadSig)

	c2 := dial(t, srv)
	m2 := helloMap(a)
	m2["pubkey"] = base64.StdEncoding.EncodeToString([]byte("short"))
	writeSigned(t, c2, a.priv, m2)
	expectErrCode(t, c2, codeBadSig)
}

func TestHelloBadSigEncoding(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	c := dial(t, srv)
	m := helloMap(a)
	signed := sign(t, a.priv, m)
	signed["sig"] = "%%%not-base64%%%"
	writeJSONFrame(t, c, signed)
	expectErrCode(t, c, codeBadSig)
}

func TestHelloStaleTS(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	c := dial(t, srv)
	m := helloMap(a)
	m["ts"] = time.Now().UnixMilli() - 301_000 // outside ±300 s
	writeSigned(t, c, a.priv, m)
	expectErrCode(t, c, codeStaleTS)
}

func TestHelloShortNonce(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	c := dial(t, srv)
	m := helloMap(a)
	m["nonce"] = "abc"
	writeSigned(t, c, a.priv, m)
	expectErrCode(t, c, codeBadFrame)
}

func TestHelloReplayedNonce(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	m := helloMap(a)
	c1 := dial(t, srv)
	writeSigned(t, c1, a.priv, m)
	readUntil(t, c1, "welcome")
	c1.CloseNow()

	c2 := dial(t, srv)
	writeSigned(t, c2, a.priv, m) // byte-identical frame
	expectErrCode(t, c2, codeReplay)
}

func TestNotAuthenticated(t *testing.T) {
	_, srv, _ := newTestHub(t)
	c := dial(t, srv)
	writeJSONFrame(t, c, map[string]any{"op": "presence_query"})
	expectErrCode(t, c, codeNotAuth)
}

func TestDoubleHello(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	c := connect(t, srv, a)
	writeSigned(t, c, a.priv, helloMap(a))
	expectErrCode(t, c, codeBadFrame)
}

func TestBadFrame(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	c := dial(t, srv)
	writeJSONFrame(t, c, "this is not json")
	expectErrCode(t, c, codeBadFrame)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageBinary, []byte("x")); err != nil {
		t.Fatal(err)
	}
	expectErrCode(t, c, codeBadFrame)

	// connection still usable after recoverable bad frames
	writeSigned(t, c, a.priv, helloMap(a))
	readUntil(t, c, "welcome")
}

func TestFrameTooLarge(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	c := connect(t, srv, a)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	big := make([]byte, maxFrameBytes+64)
	if err := c.Write(ctx, websocket.MessageText, big); err != nil {
		t.Fatal(err)
	}
	expectErrCode(t, c, codeBadFrame)
	if _, _, err := c.Reader(ctx); err == nil {
		t.Fatal("connection should be closed after oversize frame")
	}
}

func TestSendBadSignature(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca := connect(t, srv, a)
	joinChan(t, ca, a, "general", "cpub")
	m := map[string]any{"op": "send", "channel": "general", "id": "x", "ts": time.Now().UnixMilli(), "ciphertext": "QQ=="}
	writeSigned(t, ca, b.priv, m)
	expectErrCode(t, ca, codeBadSig)
}

func TestSendStaleTS(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	ca := connect(t, srv, a)
	joinChan(t, ca, a, "general", "cpub")
	m := map[string]any{"op": "send", "channel": "general", "id": "x", "ts": time.Now().UnixMilli() - 400_000, "ciphertext": "QQ=="}
	writeSigned(t, ca, a.priv, m)
	expectErrCode(t, ca, codeStaleTS)
}

// TestEndToEndCiphertext signs with ed25519, encrypts with a dedicated
// x25519 keypair, and proves the hub relays the ciphertext untouched —
// the hub is a zero-knowledge router.
func TestEndToEndCiphertext(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := withE2E(t, newAgent(t, "a")), withE2E(t, newAgent(t, "b"))
	ca, cb := connect(t, srv, a), connect(t, srv, b)

	// peers discover each other's x25519 keys via agent_info
	infoA := whois(t, cb, a.id)
	if infoA.X25519 != a.e2ePubB64 {
		t.Fatalf("agent_info x25519 %q, want %q", infoA.X25519, a.e2ePubB64)
	}
	infoB := whois(t, ca, b.id)

	const secret = "e2e payload over x25519+chacha20poly1305, signed by ed25519"
	frameID, aad := "f-1", "dap1|f-1|"+b.id
	ct := seal(t, a.e2ePriv, pubFromB64(t, infoB.X25519), frameID, aad, secret)
	sendDM(t, ca, a, b.id, frameID, ct)

	f := readUntil(t, cb, "msg")
	if f.Ciphertext != ct {
		t.Fatal("hub altered the ciphertext")
	}
	if got := unseal(t, b.e2ePriv, pubFromB64(t, infoA.X25519), frameID, aad, f.Ciphertext); got != secret {
		t.Fatalf("recipient decrypted %q, want %q", got, secret)
	}
}

func TestConstEq(t *testing.T) {
	if !constEq("token", "token") {
		t.Fatal("equal strings must compare equal")
	}
	if constEq("token", "tokeo") || constEq("short", "much-longer-string") {
		t.Fatal("different strings must compare unequal")
	}
}
