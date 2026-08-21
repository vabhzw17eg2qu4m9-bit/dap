package main

// join_presence_test.go — channel-join presence symmetry: peers get an
// online broadcast on join (offline broadcast exists on disconnect).

import (
	"net/http"
	"testing"
	"time"
)

func TestJoinBroadcastsPresence(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca := connect(t, srv, a)
	joinChan(t, ca, a, "general", "cpub")

	cb := connect(t, srv, b) // no channels yet: b's hello presence reaches nobody
	joinChan(t, cb, b, "general", "cpub")

	f := readUntilFn(t, ca, func(f frame) bool {
		return f.Op == "presence" && len(f.Agents) == 1 && f.Agents[0].AgentID == b.id && f.Agents[0].Online
	})
	if f.Agents[0].Pubkey != b.pubB64 {
		t.Fatalf("presence pubkey %q, want %q", f.Agents[0].Pubkey, b.pubB64)
	}
}

func TestJoinDeniedNoPresence(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, c := newAgent(t, "a"), newAgent(t, "c")
	ca := connect(t, srv, a)
	joinChan(t, ca, a, "general", "cpub")

	put := adminReq(t, srv.URL, http.MethodPut, "/api/channels/general/acl", adminTestToken, map[string]any{"allowed": []string{a.pubB64}})
	if put.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT acl status %d", put.StatusCode)
	}

	cc := connect(t, srv, c)
	writeSigned(t, cc, c.priv, map[string]any{"op": "join", "channel": "general", "chanPubkey": "cpub", "ts": time.Now().UnixMilli()})
	expectErrCode(t, cc, codeDenied)
	expectQuiet(t, ca, 200*time.Millisecond)
}
