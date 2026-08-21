package main

// admin_test.go — admin REST auth (constant-time bearer), channel
// listing, ACL upsert, agent listing, healthz, store round trip.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHealthz(t *testing.T) {
	_, srv, _ := newTestHub(t)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("healthz: %d %q", resp.StatusCode, body)
	}
}

func TestAdminUnauthorized(t *testing.T) {
	_, srv, _ := newTestHub(t)
	for _, tok := range []string{"", "wrong-token"} {
		resp := adminReq(t, srv.URL, http.MethodGet, "/api/channels", tok, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("token %q: status %d, want 401", tok, resp.StatusCode)
		}
	}

	// hub configured without a token rejects everything
	empty := newHub("", filepath.Join(t.TempDir(), "channels.json"), io.Discard)
	esrv := httptest.NewServer(buildMux(empty))
	t.Cleanup(esrv.Close)
	resp := adminReq(t, esrv.URL, http.MethodGet, "/api/agents", "anything", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("empty admin token: status %d, want 401", resp.StatusCode)
	}
}

func TestAdminEndpoints(t *testing.T) {
	h, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	joinChan(t, ca, a, "general", "cpub")
	joinChan(t, cb, b, "general", "cpub")
	_ = h

	resp := adminReq(t, srv.URL, http.MethodGet, "/api/channels", adminTestToken, nil)
	var rows []channelSummary
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Name != "general" || rows[0].Members != 2 || rows[0].ACLSize != 0 {
		t.Fatalf("channels rows %+v", rows)
	}

	put := adminReq(t, srv.URL, http.MethodPut, "/api/channels/general/acl", adminTestToken, map[string]any{"allowed": []string{a.pubB64}})
	if put.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT acl status %d", put.StatusCode)
	}
	resp2 := adminReq(t, srv.URL, http.MethodGet, "/api/channels", adminTestToken, nil)
	var rows2 []channelSummary
	json.NewDecoder(resp2.Body).Decode(&rows2)
	if rows2[0].ACLSize != 1 {
		t.Fatalf("acl after PUT %+v", rows2)
	}

	agents := adminReq(t, srv.URL, http.MethodGet, "/api/agents", adminTestToken, nil)
	var list []agentInfo
	if err := json.NewDecoder(agents.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("agents list %+v", list)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	h, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	joinChan(t, ca, a, "general", "cpub")
	joinChan(t, cb, b, "general", "cpub")
	adminReq(t, srv.URL, http.MethodPut, "/api/channels/general/acl", adminTestToken, map[string]any{"allowed": []string{a.pubB64}})

	raw, err := os.ReadFile(h.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("general")) || !bytes.Contains(raw, []byte(a.pubB64)) {
		t.Fatalf("store missing channel data: %s", raw)
	}

	// a fresh hub restores name, pubkey and ACL
	h2 := newHub(adminTestToken, h.storePath, io.Discard)
	h2.loadChannels()
	ch := h2.channels["general"]
	if ch == nil || ch.Pubkey != "cpub" || len(ch.Allowed) != 1 || ch.Allowed[0] != a.pubB64 {
		t.Fatalf("restored channel: %+v", ch)
	}

	// corrupt store: parse failure is logged, boot continues empty
	corrupt := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(corrupt, []byte("{not json"), 0o600)
	h3 := newHub(adminTestToken, corrupt, io.Discard)
	h3.loadChannels()
	if len(h3.channels) != 0 {
		t.Fatal("corrupt store should yield no channels")
	}
}

func TestWriteAtomicBadPath(t *testing.T) {
	if err := writeAtomic("/nonexistent-dir/out.json", channelStore{}); err == nil {
		t.Fatal("writeAtomic should fail on unwritable path")
	}
}
