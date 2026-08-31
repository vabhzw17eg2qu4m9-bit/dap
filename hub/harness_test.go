package main

// harness_test.go — shared test infrastructure: in-process hub over
// httptest, real WebSocket dials to 127.0.0.1, deterministic helpers
// (deadline reads, synchronous round-trips — no sleep-based sync).

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const (
	adminTestToken   = "test-admin-token"
	testMasterSecret = "test-master-secret"
)

func newTestHub(t *testing.T) (*hub, *httptest.Server, *bytes.Buffer) {
	t.Helper()
	logbuf := &bytes.Buffer{}
	h := newHub(hubConfig{
		AdminToken:   adminTestToken,
		MasterSecret: testMasterSecret,
		StorePath:    filepath.Join(t.TempDir(), "channels.json"),
		SecretsPath:  filepath.Join(t.TempDir(), "secrets.json"),
	}, logbuf)
	h.pingEvery = time.Hour // dedicated ping test overrides this
	srv := httptest.NewServer(buildMux(h))
	t.Cleanup(srv.Close)
	return h, srv, logbuf
}

// testAgent is a client identity: an Ed25519 signing keypair plus a
// dedicated X25519 keypair for E2E (per DAP/1: separate keys, no reuse).
type testAgent struct {
	priv      ed25519.PrivateKey
	pubB64    string
	e2ePriv   *ecdh.PrivateKey
	e2ePubB64 string
	id        string
	name      string
}

func newAgent(t *testing.T, name string) *testAgent {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testAgent{priv: priv, pubB64: base64.StdEncoding.EncodeToString(pub), id: agentIDFor(pub), name: name}
}

// sign adds "sig" over the canonical JSON of m (without sig), exactly
// as an adapter does: dap1|op|ts|hex(sha256(canonical)). Uses the same
// canonicalizer as the hub (sorted keys, no whitespace, no HTML escape).
func sign(t *testing.T, priv ed25519.PrivateKey, m map[string]any) map[string]any {
	t.Helper()
	clone := map[string]any{}
	for k, v := range m {
		if k != "sig" {
			clone[k] = v
		}
	}
	canonical, err := canonicalJSON(clone)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	tsBytes, err := json.Marshal(m["ts"])
	if err != nil {
		t.Fatal(err)
	}
	payload := "dap1|" + m["op"].(string) + "|" + string(tsBytes) + "|" + hex.EncodeToString(sum[:])
	clone["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload)))
	return clone
}

func writeJSONFrame(t *testing.T, c *websocket.Conn, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func writeSigned(t *testing.T, c *websocket.Conn, priv ed25519.PrivateKey, m map[string]any) {
	t.Helper()
	writeJSONFrame(t, c, sign(t, priv, m))
}

// dial opens /ws. bearer overrides the default master-secret header:
// pass "" for no Authorization header at all (401 path), or a full
// header value like "Bearer <issued secret>" to dial as an agent.
func dial(t *testing.T, srv *httptest.Server, bearer ...string) *websocket.Conn {
	t.Helper()
	c, err := dialConn(t, srv, bearer...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	return c
}

// dialConn is dial without the fatal: callers assert on upgrade
// rejections (HTTP 401).
func dialConn(t *testing.T, srv *httptest.Server, bearer ...string) (*websocket.Conn, error) {
	t.Helper()
	token := "Bearer " + testMasterSecret
	if len(bearer) > 0 {
		token = bearer[0]
	}
	header := http.Header{}
	if token != "" {
		header.Set("Authorization", token)
	}
	url := strings.Replace(srv.URL, "http://", "ws://", 1) + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header})
	return c, err
}

func readFrameT(t *testing.T, c *websocket.Conn, d time.Duration) (frame, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	_, r, err := c.Reader(ctx)
	if err != nil {
		return frame{}, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return frame{}, err
	}
	var f frame
	err = json.Unmarshal(data, &f)
	return f, err
}

// readRawT reads one frame as a generic map — for the frozen enroll
// wire shapes ("t" field) that do not parse into the typed frame.
func readRawT(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, r, err := c.Reader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// readUntilFn returns the first frame matching want; skip lists ops to
// ignore while waiting (presence broadcasts interleave with replies).
func readUntilFn(t *testing.T, c *websocket.Conn, want func(frame) bool, skip ...string) frame {
	t.Helper()
	for i := 0; i < 200; i++ {
		f, err := readFrameT(t, c, 2*time.Second)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if want(f) {
			return f
		}
		if !slices.Contains(skip, f.Op) {
			t.Fatalf("unexpected frame %+v", f)
		}
	}
	t.Fatal("no matching frame arrived")
	return frame{}
}

func readUntil(t *testing.T, c *websocket.Conn, op string, skip ...string) frame {
	t.Helper()
	return readUntilFn(t, c, func(f frame) bool { return f.Op == op }, skip...)
}

// readRawUntilFn returns the first raw frame (generic map) matching
// want — for wire-level assertions the typed frame cannot express
// (a field's presence vs absence).
func readRawUntilFn(t *testing.T, c *websocket.Conn, want func(map[string]any) bool) map[string]any {
	for range 200 {
		m := readRawT(t, c)
		if want(m) {
			return m
		}
	}
	t.Fatal("no matching raw frame arrived")
	return nil
}

// expectQuiet asserts no frame arrives within the window (deadline-based
// negative check — never a sleep-based sync).
func expectQuiet(t *testing.T, c *websocket.Conn, window time.Duration) {
	t.Helper()
	if f, err := readFrameT(t, c, window); err == nil {
		t.Fatalf("unexpected frame %+v", f)
	}
}

func randHexT() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func helloMap(a *testAgent) map[string]any {
	return map[string]any{"op": "hello", "v": 1, "pubkey": a.pubB64, "name": a.name, "nonce": randHexT(), "ts": time.Now().UnixMilli()}
}

// connect dials, performs hello, and asserts the welcome agentId.
func connect(t *testing.T, srv *httptest.Server, a *testAgent) *websocket.Conn {
	t.Helper()
	c := dial(t, srv)
	m := helloMap(a)
	if a.e2ePriv != nil {
		m["x25519"] = a.e2ePubB64
	}
	writeSigned(t, c, a.priv, m)
	w := readUntil(t, c, "welcome")
	if w.AgentID != a.id {
		t.Fatalf("welcome agentId %q, want %q", w.AgentID, a.id)
	}
	return c
}

func joinChan(t *testing.T, c *websocket.Conn, a *testAgent, name, chanPub string) {
	t.Helper()
	writeSigned(t, c, a.priv, map[string]any{"op": "join", "channel": name, "chanPubkey": chanPub, "ts": time.Now().UnixMilli()})
	readUntil(t, c, "joined", "presence")
}

func sendChan(t *testing.T, c *websocket.Conn, a *testAgent, ch, id, ciphertext string) {
	t.Helper()
	writeSigned(t, c, a.priv, map[string]any{"op": "send", "channel": ch, "id": id, "ts": time.Now().UnixMilli(), "ciphertext": ciphertext})
}

func sendDM(t *testing.T, c *websocket.Conn, a *testAgent, to, id, ciphertext string) {
	t.Helper()
	writeSigned(t, c, a.priv, map[string]any{"op": "send", "to": to, "id": id, "ts": time.Now().UnixMilli(), "ciphertext": ciphertext})
}

func whois(t *testing.T, c *websocket.Conn, agentID string) frame {
	t.Helper()
	writeJSONFrame(t, c, map[string]any{"op": "whois", "agentId": agentID})
	return readUntil(t, c, "agent_info", "presence")
}

// waitOffline polls whois (a synchronous round trip) until the hub has
// processed the target's disconnect — deterministic, no sleeps.
func waitOffline(t *testing.T, c *websocket.Conn, agentID string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		f := whois(t, c, agentID)
		if f.Online != nil && !*f.Online {
			return
		}
	}
	t.Fatalf("agent %s never went offline", agentID)
}
