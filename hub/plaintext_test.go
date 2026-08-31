package main

// plaintext_test.go — hard constraint #1: the hub never sees plaintext.
// Exchanges real E2E-encrypted traffic, then asserts no plaintext in
// hub state, the JSON store, or hub logs.

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestNoPlaintextInHubState(t *testing.T) {
	h, srv, logbuf := newTestHub(t)
	a, b := withE2E(t, newAgent(t, "a")), withE2E(t, newAgent(t, "b"))
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	joinChan(t, ca, a, "warroom", "chan-pub")
	joinChan(t, cb, b, "warroom", "chan-pub")

	secret := "ATTACK-AT-DAWN-" + randHexT()

	// channel message: E2E to the channel keypair
	chanPriv, chanPubB64 := newX25519Pair(t)
	chanAAD := "dap1|c1|warroom"
	ct := seal(t, chanPriv, pubFromB64(t, chanPubB64), "c1", chanAAD, secret)
	sendChan(t, ca, a, "warroom", "c1", ct)
	readUntil(t, ca, "msg", "presence") // drain a's own echo
	fc := readUntil(t, cb, "msg", "presence")
	if got := unseal(t, chanPriv, pubFromB64(t, chanPubB64), "c1", chanAAD, fc.Ciphertext); got != secret {
		t.Fatalf("channel E2E round trip failed: %q", got)
	}

	// DM: E2E from a's x25519 key to b's x25519 key (learned via whois)
	info := whois(t, ca, b.id)
	dmAAD := "dap1|d1|" + b.id
	dmCT := seal(t, a.e2ePriv, pubFromB64(t, info.X25519), "d1", dmAAD, secret)
	sendDM(t, ca, a, b.id, "d1", dmCT)
	fd := readUntil(t, cb, "msg")
	if got := unseal(t, b.e2ePriv, pubFromB64(t, a.e2ePubB64), "d1", dmAAD, fd.Ciphertext); got != secret {
		t.Fatalf("DM E2E round trip failed: %q", got)
	}
	if fd.Ciphertext == secret || bytes.Contains([]byte(fd.Ciphertext), []byte(secret)) {
		t.Fatal("ciphertext must not contain plaintext")
	}

	// hub RAM state: channels, agents, mailboxes — ciphertext only
	h.mu.RLock()
	snapshot, err := json.Marshal(map[string]any{
		"channels": h.channels, "agents": h.agents,
		"mailbox": h.mailbox, "mailboxDropped": h.mailboxDropped,
	})
	h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}

	// persisted store + logs
	storeBytes, err := os.ReadFile(h.storePath)
	if err != nil {
		t.Fatal(err)
	}

	for name, blob := range map[string][]byte{"state": snapshot, "store": storeBytes, "log": logbuf.Bytes()} {
		if bytes.Contains(blob, []byte(secret)) {
			t.Fatalf("plaintext leaked into hub %s", name)
		}
	}
}

// TestNoPlaintextIssuedSecret: the enroll reply's plaintext secret must
// never reach the secrets file (hash only) or the logs.
func TestNoPlaintextIssuedSecret(t *testing.T) {
	h, srv, logbuf := newTestHub(t)
	c := dial(t, srv)
	a := newAgent(t, "alice")
	writeSigned(t, c, a.priv, helloMap(a))
	readUntil(t, c, "welcome")
	writeJSONFrame(t, c, map[string]any{"t": "enroll"})
	reply := readRawT(t, c)
	secret, _ := reply["secret"].(string)
	if secret == "" {
		t.Fatal("no issued secret in reply")
	}
	c.CloseNow()

	secretsBytes, err := os.ReadFile(h.secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(secretsBytes, []byte(sha256Hex(secret))) {
		t.Fatal("secrets file must contain the issued hash")
	}
	for name, blob := range map[string][]byte{"secrets file": secretsBytes, "log": logbuf.Bytes()} {
		if bytes.Contains(blob, []byte(secret)) {
			t.Fatalf("issued plaintext secret leaked into hub %s", name)
		}
	}
}
