package main

// lastseen_test.go — registry lastSeen must advance on every
// authenticated inbound frame (single dispatch touchpoint), so whois /
// presence liveness reflects activity, not connect time.

import (
	"sync/atomic"
	"testing"
)

func TestLastSeenAdvancesOnAuthenticatedFrame(t *testing.T) {
	h, srv, _ := newTestHub(t)

	// Deterministic monotonic clock: every touch strictly advances.
	var clock atomic.Int64
	clock.Store(1_000)
	h.now = func() int64 { return clock.Add(1_000) }

	a := newAgent(t, "a")
	b := newAgent(t, "b")
	ca := connect(t, srv, a) // hello stamp
	cb := connect(t, srv, b)

	h.mu.RLock()
	before := h.agents[a.id].LastSeen
	h.mu.RUnlock()
	if before == 0 {
		t.Fatal("connect-time lastSeen missing")
	}

	// Authenticated activity: A DMs B. The msg on B's socket proves the
	// frame was fully processed, so the sender touchpoint already ran.
	sendDM(t, ca, a, b.id, "ls-1", "TEw=")
	if f := readUntil(t, cb, "msg"); f.ID != "ls-1" {
		t.Fatalf("DM delivered: %+v, want id ls-1", f)
	}

	h.mu.RLock()
	after := h.agents[a.id].LastSeen
	h.mu.RUnlock()
	if after <= before {
		t.Fatalf("lastSeen %d did not advance beyond connect-time %d", after, before)
	}
}
