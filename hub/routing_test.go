package main

// routing_test.go — channel broadcast, DM recipient-only delivery,
// one-conn-per-agent eviction, ping loop.

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestChannelBroadcast(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b, c := newAgent(t, "a"), newAgent(t, "b"), newAgent(t, "c")
	ca, cb, cc := connect(t, srv, a), connect(t, srv, b), connect(t, srv, c)
	joinChan(t, ca, a, "general", "chan-pub-b64")
	joinChan(t, cb, b, "general", "chan-pub-b64") // c never joins

	sendChan(t, ca, a, "general", "x1", "CIPHERTEXT-1")

	for _, conn := range []*websocket.Conn{ca, cb} {
		f := readUntil(t, conn, "msg", "presence")
		if f.Channel != "general" || f.From != a.id || f.ID != "x1" || f.Ciphertext != "CIPHERTEXT-1" {
			t.Fatalf("unexpected msg frame %+v", f)
		}
	}
	expectQuiet(t, cc, 250*time.Millisecond) // non-member receives nothing
}

func TestDirectMessage(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b, c := newAgent(t, "a"), newAgent(t, "b"), newAgent(t, "c")
	ca, cb, cc := connect(t, srv, a), connect(t, srv, b), connect(t, srv, c)

	sendDM(t, ca, a, b.id, "d1", "CT-DM-1")

	f := readUntil(t, cb, "msg")
	if f.To != b.id || f.From != a.id || f.ID != "d1" || f.Ciphertext != "CT-DM-1" {
		t.Fatalf("unexpected DM frame %+v", f)
	}
	expectQuiet(t, ca, 250*time.Millisecond) // sender gets no echo (spec)
	expectQuiet(t, cc, 250*time.Millisecond) // third agent gets nothing
}

func TestEviction(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	c1 := connect(t, srv, a)
	c2 := connect(t, srv, a) // same agentId evicts the old connection

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := c1.Reader(ctx); err == nil {
		t.Fatal("evicted connection should be closed")
	}
	w := whois(t, c2, a.id)
	if w.Online == nil || !*w.Online {
		t.Fatalf("agent should be online via new connection: %+v", w)
	}
}

func TestPingKeepsConnectionAlive(t *testing.T) {
	h, srv, _ := newTestHub(t)
	h.pingEvery = 20 * time.Millisecond
	a := newAgent(t, "p")
	c := connect(t, srv, a)
	w := whois(t, c, a.id) // round trip proves the connection is healthy
	if w.Online == nil || !*w.Online {
		t.Fatal("connection should be alive")
	}
	expectQuiet(t, c, 150*time.Millisecond) // several ping cycles: no data, no errors
}

func TestUnknownOp(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	c := connect(t, srv, a)
	writeJSONFrame(t, c, map[string]any{"op": "bogus"})
	expectErrCode(t, c, codeBadFrame)
}
