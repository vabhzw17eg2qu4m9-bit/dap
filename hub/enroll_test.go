package main

// enroll_test.go — bearer auth at the upgrade and the enroll op:
// 401s, master-token dials, secret issuance and format, name binding,
// rejection paths, re-enroll replacement, secrets-file persistence.

import (
	"encoding/base64"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWSAuthDenied(t *testing.T) {
	_, srv, _ := newTestHub(t)
	for name, header := range map[string]string{
		"missing header":     "",
		"wrong token":        "Bearer not-the-secret",
		"unknown valid form": "Bearer " + strings.Repeat("a", 64),
	} {
		_, err := dialConn(t, srv, header)
		if err == nil {
			t.Fatalf("%s: dial succeeded, want 401", name)
		}
		if !strings.Contains(err.Error(), "401") {
			t.Fatalf("%s: want 401 in error, got %v", name, err)
		}
	}
}

func TestMasterTokenConnects(t *testing.T) {
	_, srv, _ := newTestHub(t)
	c := dial(t, srv, "Bearer "+testMasterSecret)
	a := newAgent(t, "m")
	writeSigned(t, c, a.priv, helloMap(a))
	w := readUntil(t, c, "welcome")
	if w.AgentID != a.id {
		t.Fatalf("welcome agentId %q, want %q", w.AgentID, a.id)
	}
}

func TestEnrollRoundTrip(t *testing.T) {
	h, srv, _ := newTestHub(t)
	c := dial(t, srv) // master bearer by default
	alice := newAgent(t, "alice")
	writeSigned(t, c, alice.priv, helloMap(alice))
	readUntil(t, c, "welcome")

	writeJSONFrame(t, c, map[string]any{"t": "enroll"})
	reply := readRawT(t, c)
	if reply["t"] != "enrolled" {
		t.Fatalf("reply %+v, want t=enrolled", reply)
	}
	secret, _ := reply["secret"].(string)
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(raw) != 32 {
		t.Fatalf("secret %q: want base64url of 32 bytes (err=%v)", secret, err)
	}
	if h.secrets["alice"] != sha256Hex(secret) {
		t.Fatal("issued secret hash not bound to hello name")
	}
	c.CloseNow()

	// fresh dial with the issued secret: agent auth, delivery works
	c2 := dial(t, srv, "Bearer "+secret)
	writeSigned(t, c2, alice.priv, helloMap(alice))
	readUntil(t, c2, "welcome")

	b := newAgent(t, "b")
	cb := connect(t, srv, b)
	joinChan(t, cb, b, "room", "chan-pub")
	joinChan(t, c2, alice, "room", "chan-pub")
	sendChan(t, cb, b, "room", "m1", "ct-1")
	readUntil(t, c2, "msg", "presence")
}

func TestEnrolledSecretNameBinding(t *testing.T) {
	_, srv, _ := newTestHub(t)
	c := dial(t, srv)
	alice := newAgent(t, "alice")
	writeSigned(t, c, alice.priv, helloMap(alice))
	readUntil(t, c, "welcome")
	writeJSONFrame(t, c, map[string]any{"t": "enroll"})
	secret := readRawT(t, c)["secret"].(string)
	c.CloseNow()

	bob := newAgent(t, "bob")
	c2 := dial(t, srv, "Bearer "+secret)
	writeSigned(t, c2, bob.priv, helloMap(bob))
	f := readUntil(t, c2, "error")
	if f.Code != codeDenied {
		t.Fatalf("error code %q, want %q", f.Code, codeDenied)
	}
	if _, err := readFrameT(t, c2, 2*time.Second); err == nil {
		t.Fatal("connection should be closed after name mismatch")
	}
}

func TestEnrollRequiresMasterAndHello(t *testing.T) {
	_, srv, _ := newTestHub(t)

	// enroll before hello: honest error, connection still usable
	cm := dial(t, srv)
	writeJSONFrame(t, cm, map[string]any{"t": "enroll"})
	f := readUntil(t, cm, "error")
	if f.Code != codeNotAuth {
		t.Fatalf("code %q, want %q", f.Code, codeNotAuth)
	}
	cm.CloseNow()

	// enroll on a client-secret (agent) connection: honest error
	c := dial(t, srv)
	alice := newAgent(t, "alice")
	writeSigned(t, c, alice.priv, helloMap(alice))
	readUntil(t, c, "welcome")
	writeJSONFrame(t, c, map[string]any{"t": "enroll"})
	secret := readRawT(t, c)["secret"].(string)
	c.CloseNow()

	ca := dial(t, srv, "Bearer "+secret)
	writeSigned(t, ca, alice.priv, helloMap(alice))
	readUntil(t, ca, "welcome")
	writeJSONFrame(t, ca, map[string]any{"t": "enroll"})
	f = readUntil(t, ca, "error")
	if f.Code != codeDenied {
		t.Fatalf("code %q, want %q", f.Code, codeDenied)
	}
}

func TestReEnrollReplaces(t *testing.T) {
	_, srv, _ := newTestHub(t)
	c := dial(t, srv)
	alice := newAgent(t, "alice")
	writeSigned(t, c, alice.priv, helloMap(alice))
	readUntil(t, c, "welcome")
	writeJSONFrame(t, c, map[string]any{"t": "enroll"})
	old1 := readRawT(t, c)["secret"].(string)
	writeJSONFrame(t, c, map[string]any{"t": "enroll"})
	old2 := readRawT(t, c)["secret"].(string)
	if old1 == old2 {
		t.Fatal("re-enroll must issue a fresh secret")
	}
	c.CloseNow()

	if _, err := dialConn(t, srv, "Bearer "+old1); err == nil {
		t.Fatal("replaced secret must be rejected")
	}
	c2 := dial(t, srv, "Bearer "+old2)
	writeSigned(t, c2, alice.priv, helloMap(alice))
	readUntil(t, c2, "welcome")
}

func TestRunRequiresMasterSecret(t *testing.T) {
	err := run(hubConfig{
		Addr:        "127.0.0.1:0",
		AdminToken:  "x",
		StorePath:   filepath.Join(t.TempDir(), "c.json"),
		SecretsPath: filepath.Join(t.TempDir(), "s.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "master secret") {
		t.Fatalf("want master-secret error, got %v", err)
	}
}

func TestSecretsFileSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := hubConfig{
		AdminToken:   "a",
		MasterSecret: testMasterSecret,
		StorePath:    filepath.Join(dir, "channels.json"),
		SecretsPath:  filepath.Join(dir, "secrets.json"),
	}
	h := newHub(cfg, io.Discard)
	h.pingEvery = time.Hour
	srv := httptest.NewServer(buildMux(h))

	c := dial(t, srv)
	alice := newAgent(t, "alice")
	writeSigned(t, c, alice.priv, helloMap(alice))
	readUntil(t, c, "welcome")
	writeJSONFrame(t, c, map[string]any{"t": "enroll"})
	secret := readRawT(t, c)["secret"].(string)
	c.CloseNow()
	srv.Close()

	// restart with a rotated master: hashes reload, the issued secret
	// still authenticates, the old master no longer does
	cfg.MasterSecret = "rotated-master"
	h2 := newHub(cfg, io.Discard)
	h2.loadSecrets()
	srv2 := httptest.NewServer(buildMux(h2))
	t.Cleanup(srv2.Close)

	if _, err := dialConn(t, srv2); err == nil {
		t.Fatal("old master must not authenticate after rotation")
	}
	c2 := dial(t, srv2, "Bearer "+secret)
	writeSigned(t, c2, alice.priv, helloMap(alice))
	readUntil(t, c2, "welcome")
}
