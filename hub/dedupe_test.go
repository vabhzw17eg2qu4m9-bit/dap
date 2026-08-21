package main

// dedupe_test.go — send frames require an id and reject replays of a
// used id within the replay window (ingress-side dedupe).

import (
	"testing"
	"time"
)

func TestSendRequiresID(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	defer ca.CloseNow()
	defer cb.CloseNow()

	writeSigned(t, ca, a.priv, map[string]any{"op": "send", "to": b.id, "ts": time.Now().UnixMilli(), "ciphertext": "QQ=="})
	expectErrCode(t, ca, codeBadFrame)
}

func TestDuplicateDMOnce(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	defer ca.CloseNow()
	defer cb.CloseNow()

	sendDM(t, ca, a, b.id, "d1", "CT")
	if f := readUntil(t, cb, "msg"); f.ID != "d1" {
		t.Fatalf("msg id %q, want %q", f.ID, "d1")
	}

	sendDM(t, ca, a, b.id, "d1", "CT")
	expectErrCode(t, ca, codeReplay)

	// The id is part of the key and the cache stays usable: a FRESH id
	// from the same sender must deliver normally after a replay rejection.
	// (Reads must precede expectQuiet — a read deadline is fatal to a
	// coder/websocket conn.)
	sendDM(t, ca, a, b.id, "d2", "CT")
	if f := readUntil(t, cb, "msg"); f.ID != "d2" {
		t.Fatalf("fresh id after replay: got %q, want d2 (id not part of the dedupe key?)", f.ID)
	}
	expectQuiet(t, cb, 200*time.Millisecond)
}

func TestDuplicateChannelMsgOnce(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	defer ca.CloseNow()
	defer cb.CloseNow()
	joinChan(t, ca, a, "general", "cpub")
	joinChan(t, cb, b, "general", "cpub")

	sendChan(t, ca, a, "general", "c1", "CT")
	if f := readUntil(t, ca, "msg", "presence"); f.ID != "c1" {
		t.Fatalf("echo id %q, want %q", f.ID, "c1")
	}
	if f := readUntil(t, cb, "msg", "presence"); f.ID != "c1" {
		t.Fatalf("msg id %q, want %q", f.ID, "c1")
	}

	sendChan(t, ca, a, "general", "c1", "CT")
	expectErrCode(t, ca, codeReplay, "msg")

	// Fresh id after a replay rejection still delivers (pin the key shape).
	sendChan(t, ca, a, "general", "c2", "CT")
	if f := readUntil(t, cb, "msg", "presence"); f.ID != "c2" {
		t.Fatalf("fresh id after replay: got %q, want c2", f.ID)
	}
	expectQuiet(t, cb, 200*time.Millisecond)
}

// A frame REJECTED for authorization must not burn its id: the client
// retries the same id after fixing the cause (here: joining the channel).
func TestRejectedSendDoesNotLatchItsID(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	defer ca.CloseNow()
	defer cb.CloseNow()
	joinChan(t, cb, b, "general", "cpub") // b creates + joins

	sendChan(t, ca, a, "general", "same-id", "CT")
	expectErrCode(t, ca, codeDenied, "presence") // a not a member yet

	joinChan(t, ca, a, "general", "cpub")
	sendChan(t, ca, a, "general", "same-id", "CT") // retry the SAME id
	if f := readUntil(t, ca, "msg", "presence"); f.ID != "same-id" {
		t.Fatalf("retried id: got %q, want same-id (id latched on rejection?)", f.ID)
	}
}
