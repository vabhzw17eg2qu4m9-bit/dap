package main

// acl_test.go — channel ACL deny on join and publish, unknown channel /
// agent errors.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

func adminReq(t *testing.T, base, method, path, token string, body any) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestChannelACLDeniesPublish(t *testing.T) {
	_, srv, _ := newTestHub(t)
	a, b, c := newAgent(t, "a"), newAgent(t, "b"), newAgent(t, "c")
	ca, cb := connect(t, srv, a), connect(t, srv, b)
	joinChan(t, ca, a, "general", "cpub") // empty ACL: anyone may join
	joinChan(t, cb, b, "general", "cpub")

	// admin restricts the channel to a's pubkey
	resp := adminReq(t, srv.URL, http.MethodPut, "/api/channels/general/acl", adminTestToken, map[string]any{"allowed": []string{a.pubB64}})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT acl status %d", resp.StatusCode)
	}

	// b (authenticated but not on ACL) may no longer publish
	sendChan(t, cb, b, "general", "bx", "CT")
	expectErrCode(t, cb, codeDenied)

	// c may not even join
	cc := connect(t, srv, c)
	writeSigned(t, cc, c.priv, map[string]any{"op": "join", "channel": "general", "ts": time.Now().UnixMilli()})
	expectErrCode(t, cc, codeDenied)

	// a remains authorized
	sendChan(t, ca, a, "general", "ax", "CT2")
	if f := readUntil(t, ca, "msg", "presence"); f.ID != "ax" {
		t.Fatalf("acl member publish failed: %+v", f)
	}

	// routing errors (b is still a member: skip late fanout of a's msg)
	sendChan(t, cb, b, "no-such-channel", "n", "CT")
	expectErrCode(t, cb, codeUnknownChannel, "msg")
	sendDM(t, cb, b, "a00000000000000f", "d", "CT")
	expectErrCode(t, cb, codeUnknownAgent, "msg")
}
