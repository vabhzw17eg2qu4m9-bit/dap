package main

// presence_test.go — presence query/broadcast, offline mailbox with
// bounded overflow, reconnect delivery of queued messages.

import (
	"testing"
	"time"
)

func TestPresence(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	joinChan(t, ca, a, "general", "cpub")
	joinChan(t, cb, b, "general", "cpub")

	writeJSONFrame(t, ca, map[string]any{"op": "presence_query"})
	f := readUntilFn(t, ca, func(f frame) bool { return f.Op == "presence" && len(f.Agents) >= 2 }, "presence")
	byID := map[string]agentInfo{}
	for _, ai := range f.Agents {
		byID[ai.AgentID] = ai
	}
	for id := range map[string]bool{a.id: true, b.id: true} {
		if got, ok := byID[id]; !ok || !got.Online {
			t.Fatalf("presence for %s: %+v", id, got)
		}
	}

	// disconnect broadcasts presence to agents sharing a channel
	cb.CloseNow()
	readUntilFn(t, ca, func(f frame) bool {
		return f.Op == "presence" && len(f.Agents) == 1 && f.Agents[0].AgentID == b.id && !f.Agents[0].Online
	})
	w := whois(t, ca, b.id)
	if w.Online == nil || *w.Online {
		t.Fatalf("whois after disconnect should be offline: %+v", w)
	}
}

func TestOfflineMailbox(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	joinChan(t, ca, a, "general", "cpub")
	joinChan(t, cb, b, "general", "cpub")

	cb.CloseNow()
	waitOffline(t, ca, b.id)

	ids := []string{"m1", "m2", "m3"}
	for _, id := range ids {
		sendChan(t, ca, a, "general", id, "CT-"+id)
	}
	for _, id := range ids { // sender's own echo
		f := readUntil(t, ca, "msg", "presence")
		if f.ID != id {
			t.Fatalf("echo id %q, want %q", f.ID, id)
		}
	}

	cb2 := connect(t, srv, b) // reconnect
	writeJSONFrame(t, cb2, map[string]any{"op": "flush"})
	for i, id := range ids {
		f := readUntil(t, cb2, "msg")
		if f.ID != ids[i] || f.Ciphertext != "CT-"+id || f.From != a.id {
			t.Fatalf("queued msg %d: %+v", i, f)
		}
	}
	fl := readUntil(t, cb2, "flushed")
	if fl.Count != len(ids) {
		t.Fatalf("flushed count %d, want %d", fl.Count, len(ids))
	}
	expectQuiet(t, cb2, 200*time.Millisecond)
}

func TestOfflineMailboxOverflow(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	joinChan(t, ca, a, "general", "cpub")
	joinChan(t, cb, b, "general", "cpub")

	cb.CloseNow()
	waitOffline(t, ca, b.id)

	const total = mailboxCap + 5
	ids := make([]string, total)
	for i := range ids {
		ids[i] = "m" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		sendChan(t, ca, a, "general", ids[i], "CT")
		readUntil(t, ca, "msg", "presence") // drain echo
	}

	cb2 := connect(t, srv, b)
	writeJSONFrame(t, cb2, map[string]any{"op": "flush"})
	for i := 0; i < mailboxCap; i++ { // oldest 5 dropped
		f := readUntil(t, cb2, "msg")
		if f.ID != ids[total-mailboxCap+i] {
			t.Fatalf("mailbox slot %d: id %q, want %q (oldest must drop)", i, f.ID, ids[total-mailboxCap+i])
		}
	}
	expectErrCode(t, cb2, codeMailboxFull) // reported exactly once
	fl := readUntil(t, cb2, "flushed")
	if fl.Count != mailboxCap {
		t.Fatalf("flushed count %d, want %d", fl.Count, mailboxCap)
	}

	writeJSONFrame(t, cb2, map[string]any{"op": "flush"}) // second flush: no repeat
	fl2 := readUntil(t, cb2, "flushed")
	if fl2.Count != 0 {
		t.Fatalf("second flush count %d, want 0", fl2.Count)
	}
	expectQuiet(t, cb2, 200*time.Millisecond)
}

func TestReconnect(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)

	cb.CloseNow()
	waitOffline(t, ca, b.id)
	sendDM(t, ca, a, b.id, "dm1", "CT-DM") // DM to offline agent → mailbox
	expectQuiet(t, ca, 200*time.Millisecond)

	cb2 := connect(t, srv, b) // reconnect + flush re-receives queued DM
	writeJSONFrame(t, cb2, map[string]any{"op": "flush"})
	f := readUntil(t, cb2, "msg")
	if f.ID != "dm1" || f.From != a.id || f.To != b.id || f.Ciphertext != "CT-DM" {
		t.Fatalf("queued DM: %+v", f)
	}
	fl := readUntil(t, cb2, "flushed")
	if fl.Count != 1 {
		t.Fatalf("flushed count %d, want 1", fl.Count)
	}
}
