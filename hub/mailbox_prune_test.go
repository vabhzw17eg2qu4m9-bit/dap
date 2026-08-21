package main

// regression: DM delivery vs registry pruning.
//
// The agent registry exists so an offline peer stays addressable (whois,
// mailbox enqueue). An earlier patch pruned identities lazily from inside
// the delivery path; the FIRST direct message to an agent offline >30min
// (mailbox still empty — nothing had arrived yet) hit unknown_agent and was
// dropped instead of enqueued. The registry is deliberately unpruned now;
// this test pins that decision.

import (
	"testing"
	"time"
)

func TestDMToLongOfflineAgentIsEnqueuedNotRejected(t *testing.T) {
	h, srv, _ := newTestHub(t)
	defer srv.Close()

	a := newAgent(t, "a")
	ca := connect(t, srv, a)
	defer ca.CloseNow()

	// B connects once so the registry learns the identity, then leaves.
	b := newAgent(t, "b")
	cb := connect(t, srv, b)
	cb.CloseNow()
	waitOffline(t, ca, b.id)

	// Far past any grace period (injectable clock).
	h.now = func() int64 { return time.Now().Add(24 * time.Hour).UnixMilli() }

	// A's DM must land in B's mailbox, not error unknown_agent.
	sendDM(t, ca, a, b.id, "dm-1", "Y3liZXI=")

	expectQuiet(t, ca, 300*time.Millisecond) // no error frame may come back

	h.mu.RLock()
	q := h.mailbox[b.id]
	h.mu.RUnlock()
	if len(q) != 1 {
		t.Fatalf("mailbox for b: got %d frames, want 1 (DM dropped — identity pruned on the delivery path?)", len(q))
	}
	if q[0].Ciphertext == "" {
		t.Fatal("queued frame carries no ciphertext")
	}
}
