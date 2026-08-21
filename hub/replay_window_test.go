package main

import (
	"testing"
	"time"
)

// Regression: replayKeep used to be 2 min while tsWindow is ±300 s,
// leaving a 3-minute replay gap. A hello nonce must be held for the
// full freshness window plus margin.
func TestNonceHeldBeyondTsWindow(t *testing.T) {
	n := newNonceCache()
	now := time.Now()
	const nonce = "nonce-aaaaaaaaaaaa" // >= nonceMinLen
	if !n.check("pub", nonce, now) {
		t.Fatal("first use must be accepted")
	}
	if n.check("pub", nonce, now.Add(4*time.Minute)) {
		t.Fatal("replay at t+4min must be rejected: nonce must be held for the full tsWindow")
	}
	if !n.check("pub", nonce, now.Add(replayKeep+time.Second)) {
		t.Fatal("nonce must expire after replayKeep")
	}
}
