package main

// admin_evict_test.go — DELETE /api/agents/{agentId}: owner-controlled
// registry eviction (explicit admin action, never automatic).

import (
	"bytes"
	"net/http"
	"os"
	"testing"
)

func TestAdminEvictOffline(t *testing.T) {
	h, srv, _ := newTestHub(t)
	ca, cb, a, _ := connectPair(t, srv)

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

// TestAdminEvictPurgesIssuedSecret: with no other registry entry holding
// the hello name, eviction must drop the issued secret from memory and
// rewrite the persisted secrets file without it.
func TestAdminEvictPurgesIssuedSecret(t *testing.T) {
	h, srv, _ := newTestHub(t)
	c, a, secret := dialAndEnroll(t, srv)
	peer := newAgent(t, "b")
	cp := connect(t, srv, peer)
	c.CloseNow()
	waitOffline(t, cp, a.id)

	resp := adminReq(t, srv.URL, http.MethodDelete, "/api/agents/"+a.id, adminTestToken, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("evict status %d, want 204", resp.StatusCode)
	}
	h.mu.RLock()
	_, inMem := h.secrets["alice"]
	h.mu.RUnlock()
	if inMem {
		t.Fatal("evicted agent's issued secret still in memory")
	}
	file, err := os.ReadFile(h.secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(file, []byte("alice")) || bytes.Contains(file, []byte(sha256Hex(secret))) {
		t.Fatal("secrets file still contains the evicted name or hash")
	}
}

// TestAdminEvictKeepsSharedNameSecret: secrets are keyed by hello NAME,
// which two enrollments can share; evicting one holder must keep the
// secret so the survivor can still dial in.
func TestAdminEvictKeepsSharedNameSecret(t *testing.T) {
	h, srv, logbuf := newTestHub(t)
	h.mu.Lock()
	h.agents["id-a"] = &agentEntry{Name: "twin"}
	h.agents["id-b"] = &agentEntry{Name: "twin"}
	h.secrets["twin"] = "deadbeef"
	h.persistSecrets()
	h.mu.Unlock()

	resp := adminReq(t, srv.URL, http.MethodDelete, "/api/agents/id-a", adminTestToken, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("evict status %d, want 204", resp.StatusCode)
	}
	h.mu.RLock()
	hash, kept := h.secrets["twin"]
	remaining := 0
	for _, e := range h.agents {
		if e.Name == "twin" {
			remaining++
		}
	}
	h.mu.RUnlock()
	if !kept || hash != "deadbeef" {
		t.Fatal("secret for a shared name was purged; survivor dial-in breaks")
	}
	if remaining != 1 {
		t.Fatalf("remaining registry entries named twin: %d, want 1", remaining)
	}
	if !bytes.Contains(logbuf.Bytes(), []byte("secret_purge=skipped")) {
		t.Fatal("skipped secret purge not logged")
	}
	file, err := os.ReadFile(h.secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(file, []byte("deadbeef")) {
		t.Fatal("secrets file lost the shared name's hash")
	}
}
