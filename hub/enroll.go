package main

// enroll.go — bearer authentication at the WebSocket upgrade and the
// enroll op. A connection presenting HUB_MASTER_SECRET may exchange it
// for a per-agent client secret; only the sha256 hash is persisted, the
// plaintext lives exclusively inside the enroll reply.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

const secretBytes = 32 // issued secrets: 32 random bytes, base64url raw

// authKind records how a connection authenticated at the upgrade.
type authKind int

const (
	authNone   authKind = iota // denied before the upgrade; never post-accept
	authMaster                 // bearer matched the master secret (may enroll)
	authAgent                  // bearer matched an issued client secret
)

// enrolledReply is the frozen enroll reply shape. It uses the legacy
// "t" field, not the standard "op", so it marshals to its own struct.
type enrolledReply struct {
	T      string `json:"t"`
	Secret string `json:"secret"`
}

// bearerToken extracts the bearer credential from the Authorization
// header ("" when absent). Shared by the admin and ws auth paths.
func bearerToken(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// wsAuth authenticates the upgrade before websocket.Accept: the master
// secret grants authMaster (enrollment capable); a persisted secret
// hash grants authAgent bound to its enrolled name; anything else is a
// plain 401, logged like the admin API.
func (h *hub) wsAuth(w http.ResponseWriter, r *http.Request) (authKind, string, bool) {
	if kind, name, ok := h.matchBearer(bearerToken(r)); ok {
		return kind, name, true
	}
	h.logf("ws", "remote", r.RemoteAddr, "result", "denied")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return authNone, "", false
}

// matchBearer classifies an upgrade token: master, issued agent secret,
// or neither.
func (h *hub) matchBearer(token string) (authKind, string, bool) {
	if h.isMaster(token) {
		return authMaster, "", true
	}
	if name, ok := h.agentForSecret(token); ok {
		return authAgent, name, true
	}
	return authNone, "", false
}

// isMaster reports whether token is the enrollment master secret.
func (h *hub) isMaster(token string) bool {
	return token != "" && h.masterSecret != "" && constEq(token, h.masterSecret)
}

// agentForSecret resolves a bearer token to the enrolled name whose
// issued client secret it matches.
func (h *hub) agentForSecret(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	want := sha256Hex(token)
	h.mu.RLock()
	defer h.mu.RUnlock()
	for name, hash := range h.secrets {
		if constEq(hash, want) {
			return name, true
		}
	}
	return "", false
}

// handleEnroll issues a fresh client secret bound to the hello name and
// persists its hash. Dispatch guarantees hello already completed; the
// master check is the enrollment gate. Re-enroll replaces the old
// secret, which then fails every new dial.
func (h *hub) handleEnroll(cl *client, _ frame, _ map[string]any) {
	if cl.auth != authMaster {
		h.sendErr(cl, codeDenied, "enroll requires the hub master secret")
		return
	}
	raw := make([]byte, secretBytes)
	rand.Read(raw) // crypto/rand.Read never fails (Go 1.24+)
	secret := base64.RawURLEncoding.EncodeToString(raw)
	h.mu.Lock()
	h.secrets[cl.name] = sha256Hex(secret)
	h.persistSecrets()
	h.mu.Unlock()
	h.logf("enroll", "agent", cl.logAgent(), "name", cl.name)
	cl.sendFrame(enrolledReply{T: "enrolled", Secret: secret})
}

// secretRecord is the on-disk shape of one issued secret: hash only.
type secretRecord struct {
	Name string `json:"name"`
	Hash string `json:"hash"` // hex sha256 of the base64url secret
}

type secretFile struct {
	Secrets []secretRecord `json:"secrets"`
}

// persistSecrets writes the secrets file atomically. Caller holds h.mu.
func (h *hub) persistSecrets() {
	records := make([]secretRecord, 0, len(h.secrets))
	for name, hash := range h.secrets {
		records = append(records, secretRecord{Name: name, Hash: hash})
	}
	if err := writeAtomic(h.secretsPath, secretFile{Secrets: records}); err != nil {
		h.log.Printf("store: write %s failed: %v", h.secretsPath, err)
	}
}

// loadSecrets restores issued secret hashes from disk. A missing file
// is not an error (first boot).
func (h *hub) loadSecrets() {
	b, err := os.ReadFile(h.secretsPath)
	if err != nil {
		return
	}
	var sf secretFile
	if err := json.Unmarshal(b, &sf); err != nil {
		h.log.Printf("store: parse %s failed: %v", h.secretsPath, err)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, rec := range sf.Secrets {
		h.secrets[rec.Name] = rec.Hash
	}
}

// sha256Hex is the digest form used for every issued-secret hash.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
