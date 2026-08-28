package main

// dm_drop_fallback_test.go — deliverDM when the recipient's registered
// connection dies between the clients-map lookup and the push: the frame
// must fall back to the offline mailbox instead of vanishing with ok:true.

import (
	"testing"
	"time"
)

func TestDMDroppedConnFallsBackToMailbox(t *testing.T) {
	h, srv, logbuf := newTestHub(t)
	a := newAgent(t, "a")
	b := newAgent(t, "b")
	ca := connect(t, srv, a)
	_ = connect(t, srv, b)

	// Kill B's connection server-side, let deregister finish, then
	// re-insert the corpse into h.clients — the exact lookup/push race
	// window the mailbox fallback covers.
	h.mu.Lock()
	dead := h.clients[b.id]
	h.mu.Unlock()
	dead.drop()
	waitOffline(t, ca, b.id)
	h.mu.Lock()
	h.clients[b.id] = dead
	h.mu.Unlock()

	sendDM(t, ca, a, b.id, "race-1", "Q1JD")
	expectQuiet(t, ca, 200*time.Millisecond) // ok:true — and nothing lost

	h.mu.RLock()
	q := h.mailbox[b.id]
	h.mu.RUnlock()
	if len(q) != 1 || q[0].ID != "race-1" {
		t.Fatalf("mailbox after dropped conn: %+v, want the single race-1 DM\nhub log:\n%s", q, logbuf.String())
	}

	// The real B reconnects (register evicts the corpse) and the flush
	// delivers the queued DM.
	cb2 := connect(t, srv, b)
	writeJSONFrame(t, cb2, map[string]any{"op": "flush"})
	if f := readUntil(t, cb2, "msg"); f.ID != "race-1" || f.Ciphertext != "Q1JD" {
		t.Fatalf("flushed DM: %+v", f)
	}
	readUntil(t, cb2, "flushed")
}
