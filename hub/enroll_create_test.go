package main

// enroll_create_test.go — independent same-name credentials and the
// compatibility contract shared with legacy enroll and persisted stores.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// enrollWithOp performs one master-authenticated enrollment for a and
// returns the issued plaintext secret. Both enrollment ops share the
// frozen enrolled reply shape.
func enrollWithOp(t *testing.T, srv *httptest.Server, a *testAgent, op string) string {
	t.Helper()
	c := dial(t, srv)
	writeSigned(t, c, a.priv, helloMap(a))
	readUntil(t, c, "welcome")
	writeJSONFrame(t, c, map[string]any{"t": op})
	reply := readRawT(t, c)
	if reply["t"] != "enrolled" {
		t.Fatalf("%s reply %+v, want t=enrolled", op, reply)
	}
	if len(reply) != 2 {
		t.Fatalf("%s reply %+v, want only t and secret", op, reply)
	}
	secret, ok := reply["secret"].(string)
	if !ok {
		t.Fatalf("%s secret is not a string: %+v", op, reply["secret"])
	}
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(raw) != secretBytes {
		t.Fatalf("%s secret: want base64url of %d bytes (err=%v)", op, secretBytes, err)
	}
	c.CloseNow()
	return secret
}

func readSecretRecords(t *testing.T, path string) []secretRecord {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var sf secretFile
	if err := json.Unmarshal(b, &sf); err != nil {
		t.Fatal(err)
	}
	return sf.Secrets
}

func TestEnrollCreateAddsIndependentSameNameCredentials(t *testing.T) {
	h, srv, _ := newTestHub(t)
	first := newAgent(t, "alice")
	second := newAgent(t, "alice")
	if first.id == second.id {
		t.Fatal("test identities must have distinct agentIds")
	}
	firstSecret := enrollWithOp(t, srv, first, "enroll_create")
	secondSecret := enrollWithOp(t, srv, second, "enroll_create")
	if firstSecret == secondSecret {
		t.Fatal("enroll_create must issue a fresh secret")
	}

	// Duplicate names in the existing array format represent independent
	// credentials; creating the second must not replace the first.
	records := readSecretRecords(t, h.secretsPath)
	want := map[string]bool{sha256Hex(firstSecret): true, sha256Hex(secondSecret): true}
	if len(records) != len(want) {
		t.Fatalf("persisted records %+v, want two", records)
	}
	for _, rec := range records {
		if rec.Name != "alice" || !want[rec.Hash] {
			t.Fatalf("unexpected persisted record %+v", rec)
		}
		delete(want, rec.Hash)
	}
	if len(want) != 0 {
		t.Fatalf("missing persisted hashes: %v", want)
	}

	// Different Ed25519 keys remain different agents despite the shared
	// display name, so neither secret connection evicts the other.
	c1 := dial(t, srv, "Bearer "+firstSecret)
	writeSigned(t, c1, first.priv, helloMap(first))
	if w := readUntil(t, c1, "welcome"); w.AgentID != first.id {
		t.Fatalf("first welcome agentId %q, want %q", w.AgentID, first.id)
	}
	c2 := dial(t, srv, "Bearer "+secondSecret)
	writeSigned(t, c2, second.priv, helloMap(second))
	if w := readUntil(t, c2, "welcome"); w.AgentID != second.id {
		t.Fatalf("second welcome agentId %q, want %q", w.AgentID, second.id)
	}
	if info := whois(t, c1, second.id); info.Name != "alice" || info.Online == nil || !*info.Online {
		t.Fatalf("second identity not simultaneously online: %+v", info)
	}
	if info := whois(t, c2, first.id); info.Name != "alice" || info.Online == nil || !*info.Online {
		t.Fatalf("first identity was evicted or renamed: %+v", info)
	}
}

func TestLegacyEnrollRevokesAllCredentialsForName(t *testing.T) {
	h, srv, _ := newTestHub(t)
	first := newAgent(t, "alice")
	second := newAgent(t, "alice")
	other := newAgent(t, "bob")
	oldFirst := enrollWithOp(t, srv, first, "enroll_create")
	oldSecond := enrollWithOp(t, srv, second, "enroll_create")
	otherSecret := enrollWithOp(t, srv, other, "enroll_create")
	replacement := enrollWithOp(t, srv, first, "enroll")

	want := map[string]string{sha256Hex(replacement): "alice", sha256Hex(otherSecret): "bob"}
	records := readSecretRecords(t, h.secretsPath)
	if len(records) != len(want) {
		t.Fatalf("persisted records after rotation %+v, want one per name", records)
	}
	for _, rec := range records {
		if want[rec.Hash] != rec.Name {
			t.Fatalf("stale or incorrectly bound record after rotation: %+v", rec)
		}
		delete(want, rec.Hash)
	}
	for label, secret := range map[string]string{"first": oldFirst, "second": oldSecond} {
		if c, err := dialConn(t, srv, "Bearer "+secret); err == nil {
			c.CloseNow()
			t.Fatalf("%s pre-rotation secret still authenticates", label)
		}
	}
	c := dial(t, srv, "Bearer "+replacement)
	writeSigned(t, c, first.priv, helloMap(first))
	readUntil(t, c, "welcome")

	// Rotation is scoped to the hello name, not a global reset.
	co := dial(t, srv, "Bearer "+otherSecret)
	writeSigned(t, co, other.priv, helloMap(other))
	readUntil(t, co, "welcome")
}

func TestEnrollCreateRequiresMasterAndHello(t *testing.T) {
	_, srv, _ := newTestHub(t)

	cm := dial(t, srv)
	writeJSONFrame(t, cm, map[string]any{"t": "enroll_create"})
	if f := readUntil(t, cm, "error"); f.Code != codeNotAuth {
		t.Fatalf("pre-hello code %q, want %q", f.Code, codeNotAuth)
	}
	cm.CloseNow()

	alice := newAgent(t, "alice")
	secret := enrollWithOp(t, srv, alice, "enroll_create")
	ca := dial(t, srv, "Bearer "+secret)
	writeSigned(t, ca, alice.priv, helloMap(alice))
	readUntil(t, ca, "welcome")
	writeJSONFrame(t, ca, map[string]any{"t": "enroll_create"})
	if f := readUntil(t, ca, "error"); f.Code != codeDenied {
		t.Fatalf("agent-auth code %q, want %q", f.Code, codeDenied)
	}
}

func TestEnrollCreateSecretNameBinding(t *testing.T) {
	_, srv, _ := newTestHub(t)
	alice := newAgent(t, "alice")
	secret := enrollWithOp(t, srv, alice, "enroll_create")

	bob := newAgent(t, "bob")
	c := dial(t, srv, "Bearer "+secret)
	writeSigned(t, c, bob.priv, helloMap(bob))
	if f := readUntil(t, c, "error"); f.Code != codeDenied {
		t.Fatalf("name mismatch code %q, want %q", f.Code, codeDenied)
	}
}

func TestEnrollCreateSecretsSurviveReload(t *testing.T) {
	dir := t.TempDir()
	cfg := hubConfig{
		AdminToken:   adminTestToken,
		MasterSecret: testMasterSecret,
		StorePath:    filepath.Join(dir, "channels.json"),
		SecretsPath:  filepath.Join(dir, "secrets.json"),
	}
	h := newHub(cfg, io.Discard)
	h.pingEvery = time.Hour
	srv := httptest.NewServer(buildMux(h))
	first := newAgent(t, "alice")
	second := newAgent(t, "alice")
	firstSecret := enrollWithOp(t, srv, first, "enroll_create")
	secondSecret := enrollWithOp(t, srv, second, "enroll_create")
	srv.Close()

	h2 := newHub(cfg, io.Discard)
	h2.pingEvery = time.Hour
	h2.loadSecrets()
	srv2 := httptest.NewServer(buildMux(h2))
	t.Cleanup(srv2.Close)
	for _, tc := range []struct {
		agent  *testAgent
		secret string
	}{{first, firstSecret}, {second, secondSecret}} {
		c := dial(t, srv2, "Bearer "+tc.secret)
		writeSigned(t, c, tc.agent.priv, helloMap(tc.agent))
		if w := readUntil(t, c, "welcome"); w.AgentID != tc.agent.id {
			t.Fatalf("welcome agentId %q, want %q", w.AgentID, tc.agent.id)
		}
	}
}

func TestLegacySecretsFileLoads(t *testing.T) {
	dir := t.TempDir()
	aliceSecret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, secretBytes))
	bobSecret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, secretBytes))
	legacy := secretFile{Secrets: []secretRecord{
		{Name: "alice", Hash: sha256Hex(aliceSecret)},
		{Name: "bob", Hash: sha256Hex(bobSecret)},
	}}
	b, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secrets.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHub(hubConfig{SecretsPath: path}, io.Discard)
	h.loadSecrets()
	for _, tc := range []struct {
		name   string
		secret string
	}{{"alice", aliceSecret}, {"bob", bobSecret}} {
		if name, ok := h.agentForSecret(tc.secret); !ok || name != tc.name {
			t.Fatalf("legacy secret for %s resolved as %q, %v", tc.name, name, ok)
		}
	}
}

func TestAdminEvictRetainsThenPurgesAllNameCredentials(t *testing.T) {
	h, srv, _ := newTestHub(t)
	first := newAgent(t, "alice")
	second := newAgent(t, "alice")
	firstSecret := enrollWithOp(t, srv, first, "enroll_create")
	secondSecret := enrollWithOp(t, srv, second, "enroll_create")
	observer := newAgent(t, "observer")
	co := connect(t, srv, observer)
	waitOffline(t, co, first.id)
	waitOffline(t, co, second.id)

	resp := adminReq(t, srv.URL, http.MethodDelete, "/api/agents/"+first.id, adminTestToken, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("first evict status %d, want 204", resp.StatusCode)
	}
	for label, secret := range map[string]string{"first": firstSecret, "second": secondSecret} {
		if name, ok := h.agentForSecret(secret); !ok || name != "alice" {
			t.Fatalf("%s credential purged while name still registered", label)
		}
	}

	resp = adminReq(t, srv.URL, http.MethodDelete, "/api/agents/"+second.id, adminTestToken, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("last evict status %d, want 204", resp.StatusCode)
	}
	for label, secret := range map[string]string{"first": firstSecret, "second": secondSecret} {
		if _, ok := h.agentForSecret(secret); ok {
			t.Fatalf("%s credential survived final name eviction", label)
		}
	}
	for _, rec := range readSecretRecords(t, h.secretsPath) {
		if rec.Name == "alice" {
			t.Fatalf("persisted credential survived final name eviction: %+v", rec)
		}
	}
}
