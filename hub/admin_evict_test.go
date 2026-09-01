package main

// admin_evict_test.go — DELETE /api/agents/{agentId}: owner-controlled
// registry eviction (explicit admin action, never automatic).

import (
	"net/http"
	"testing"
)

func TestAdminEvictOffline(t *testing.T) {
	h, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)

	// a disconnects; the identity and a queued mailbox frame remain.
	ca.CloseNow()
	waitOffline(t, cb, a.id)
	h.enqueue(a.id, frame{Op: "send", ID: "m1"})
	h.mu.Lock()
	h.mailboxDropped[a.id] = true
	h.mu.Unlock()

	resp := adminReq(t, srv.URL, http.MethodDelete, "/api/agents/"+a.id, adminTestToken, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("evict status %d, want 204", resp.StatusCode)
	}
	for _, e := range h.presenceList() {
		if e.AgentID == a.id {
			t.Fatalf("agent %s still in registry: %+v", a.id, e)
		}
	}
	h.mu.RLock()
	q, dropped := h.mailbox[a.id], h.mailboxDropped[a.id]
	h.mu.RUnlock()
	if len(q) != 0 || dropped {
		t.Fatalf("mailbox not dropped: q=%v dropped=%v", q, dropped)
	}
}

func TestAdminEvictOnline(t *testing.T) {
	h, srv, _ := newTestHub(t)
	a := newAgent(t, "a")
	ca := connect(t, srv, a)
	defer ca.CloseNow()

	resp := adminReq(t, srv.URL, http.MethodDelete, "/api/agents/"+a.id, adminTestToken, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("online evict status %d, want 409", resp.StatusCode)
	}
	var found bool
	for _, e := range h.presenceList() {
		if e.AgentID == a.id && e.Online {
			found = true
		}
	}
	if !found {
		t.Fatal("online agent evicted; entry must stay until disconnect")
	}
}

func TestAdminEvictUnknown(t *testing.T) {
	_, srv, _ := newTestHub(t)
	resp := adminReq(t, srv.URL, http.MethodDelete, "/api/agents/no-such-agent", adminTestToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown evict status %d, want 404", resp.StatusCode)
	}
}

func TestAdminEvictUnauthorized(t *testing.T) {
	_, srv, _ := newTestHub(t)
	for _, tok := range []string{"", "wrong-token"} {
		resp := adminReq(t, srv.URL, http.MethodDelete, "/api/agents/anyone", tok, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("token %q: status %d, want 401", tok, resp.StatusCode)
		}
	}
}
