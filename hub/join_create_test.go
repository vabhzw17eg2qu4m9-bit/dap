package main

import (
	"testing"
	"time"
)

// Channel creation is a master privilege (shared-hub anti-spam):
// client-secret connections may join only existing channels.
func TestClientSecretJoinCannotCreateChannel(t *testing.T) {
	h, srv, _ := newTestHub(t)
	c, alice, secret := dialAndEnroll(t, srv)
	c.CloseNow()

	c2 := dial(t, srv, "Bearer "+secret)
	writeSigned(t, c2, alice.priv, helloMap(alice))
	readUntil(t, c2, "welcome")

	writeSigned(t, c2, alice.priv, map[string]any{
		"op": "join", "channel": "fresh-room", "chanPubkey": "chan-pub",
		"ts": time.Now().UnixMilli(),
	})
	f := readUntil(t, c2, "error")
	if f.Code != codeDenied {
		t.Fatalf("code %q, want %q", f.Code, codeDenied)
	}
	h.mu.Lock()
	_, exists := h.channels["fresh-room"]
	h.mu.Unlock()
	if exists {
		t.Fatal("denied join must not create the channel")
	}
}

// The master connection creates; the enrolled agent then joins the
// existing channel with its client secret — the fa_network flow.
func TestMasterCreatesThenClientSecretJoins(t *testing.T) {
	_, srv, _ := newTestHub(t)
	c, alice, secret := dialAndEnroll(t, srv)
	joinChan(t, c, alice, "made-by-master", "chan-pub")
	c.CloseNow()

	c2 := dial(t, srv, "Bearer "+secret)
	writeSigned(t, c2, alice.priv, helloMap(alice))
	readUntil(t, c2, "welcome")
	joinChan(t, c2, alice, "made-by-master", "chan-pub")
}
