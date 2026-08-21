package main

// membership_test.go — channel publish requires membership (in addition
// to the ACL); ACL still enforced for members.

import (
	"net/http"
	"testing"
)

func TestNonMemberPublishDenied(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	joinChan(t, ca, a, "general", "cpub") // empty ACL: open, but b never joined

	sendChan(t, cb, b, "general", "x", "CT")
	expectErrCode(t, cb, codeDenied)
}

func TestMemberPublishAfterJoin(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	joinChan(t, ca, a, "general", "cpub")
	joinChan(t, cb, b, "general", "cpub")

	sendChan(t, cb, b, "general", "y", "CT")
	if f := readUntil(t, ca, "msg", "presence"); f.ID != "y" {
		t.Fatalf("a missing fanout: %+v", f)
	}
	if f := readUntil(t, cb, "msg", "presence"); f.ID != "y" {
		t.Fatalf("b missing echo: %+v", f)
	}
}

func TestMembershipDoesNotBypassACL(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b := newAgent(t, "a"), newAgent(t, "b")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	joinChan(t, ca, a, "general", "cpub")
	joinChan(t, cb, b, "general", "cpub")

	// admin restricts the channel to a's pubkey; b is a member but off ACL
	resp := adminReq(t, srv.URL, http.MethodPut, "/api/channels/general/acl", adminTestToken, map[string]any{"allowed": []string{a.pubB64}})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT acl status %d", resp.StatusCode)
	}

	sendChan(t, cb, b, "general", "bz", "CT")
	expectErrCode(t, cb, codeDenied)
}
