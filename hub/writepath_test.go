package main

// writepath_test.go — write-pump exclusivity (reject flows through the
// pump) and the per-client queued-bytes cap (slow consumers are shed).

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestRejectFrameDeliveredThenClose: a rejected hello gets its error frame
// delivered by the write pump — racing an earlier queued bad_frame error —
// then the connection closes (reject is fatal).
func TestRejectFrameDeliveredThenClose(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a := newAgent(t, "rejectee")
	c := dial(t, srv)

	// binary frame first: pump-queues a bad_frame error, conn stays up
	wctx, wcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer wcancel()
	if err := c.Write(wctx, websocket.MessageBinary, []byte("x")); err != nil {
		t.Fatal(err)
	}

	// unsigned hello: reject hands the frame to the pump, which may still
	// hold the earlier bad_frame error — skip error frames until bad_sig
	writeJSONFrame(t, c, helloMap(a))
	readUntilFn(t, c, func(f frame) bool { return f.Code == codeBadSig }, "error")

	rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer rcancel()
	if _, _, err := c.Reader(rctx); err == nil {
		t.Fatal("connection still readable after reject")
	}
}

// TestSlowConsumerDropped: flooding a channel faster than one member
// drains sheds the victim at the queue cap; the healthy sender survives.
func TestSlowConsumerDropped(t *testing.T) {
	h, srv, _ := newTestHub(t)
	a, v := newAgent(t, "sender"), newAgent(t, "victim")
	ca, cv := connect(t, srv, a), connect(t, srv, v)
	joinChan(t, ca, a, "general", "cpub")
	joinChan(t, cv, v, "general", "cpub")

	h.mu.RLock()
	vcl := h.clients[v.id]
	h.mu.RUnlock()
	if vcl == nil {
		t.Fatal("victim client not registered")
	}

	// victim never reads; sender drains its own fanout echo per send.
	// 48 x ~700KB (~33MB) is far past loopback TCP buffering, so the
	// victim's queue provably crosses maxQueuedBytes and it gets shed.
	ca.SetReadLimit(2 * maxFrameBytes) // echoes carry ~700KB ciphertext
	ct := strings.Repeat("Q", 700_000) // < maxFrameBytes on the wire
	for i := 0; i < 48; i++ {
		sendChan(t, ca, a, "general", fmt.Sprintf("flood-%d", i), ct)
		readUntil(t, ca, "msg", "presence")
	}

	waitOffline(t, ca, v.id)
	if q := vcl.queued.Load(); q > int64(maxQueuedBytes+maxFrameBytes) {
		t.Fatalf("victim queued %d bytes, over cap slack %d", q, int64(maxQueuedBytes+maxFrameBytes))
	}
	if w := whois(t, ca, a.id); w.Online == nil || !*w.Online {
		t.Fatalf("sender unhealthy after flood: %+v", w)
	}
}
