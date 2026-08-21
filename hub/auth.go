package main

// auth.go — hello handshake, Ed25519 envelope verification, replay cache.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	tsWindow    = 300_000 // ms, spec: ±300 s
	replayKeep  = 2 * time.Minute
	nonceMinLen = 16
)

// constEq compares two strings in constant time (hash first so length
// does not leak). Used on every credential-comparison path.
func constEq(a, b string) bool {
	ah := sha256.Sum256([]byte(a))
	bh := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}

// agentIDFor derives the agentId: hex(sha256(pubkey_raw))[:16].
func agentIDFor(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// canonicalJSON marshals with sorted keys and no whitespace. Per DAP/1
// addendum: HTML escaping is disabled (SetEscapeHTML(false)) so Go,
// JS and Dart canonicalizers produce identical bytes.
func canonicalJSON(v map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// signedPayloadFor builds the canonical signing payload:
//
//	"dap1|" + op + "|" + ts + "|" + hex(sha256(canonicalJSON(frame minus sig)))
//
// encoding/json sorts map keys, so marshaling the decoded raw map is
// the canonical form (numbers keep their literal via json.Number).
func signedPayloadFor(raw map[string]any, f frame) (string, error) {
	if f.Sig == "" {
		return "", errors.New("missing sig")
	}
	clone := make(map[string]any, len(raw))
	for k, v := range raw {
		clone[k] = v
	}
	delete(clone, "sig")
	canonical, err := canonicalJSON(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "dap1|" + f.Op + "|" + strconv.FormatInt(f.TS, 10) + "|" + hex.EncodeToString(sum[:]), nil
}

// verifySignature checks the Ed25519 signature over the canonical
// payload. pubB64 is the signing key: self-declared in hello, the
// authenticated connection key for every later frame.
func verifySignature(f frame, raw map[string]any, pubB64 string) *protoError {
	payload, err := signedPayloadFor(raw, f)
	if err != nil {
		return &protoError{codeBadSig, err.Error()}
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return &protoError{codeBadSig, "bad pubkey"}
	}
	sig, err := base64.StdEncoding.DecodeString(f.Sig)
	if err != nil {
		return &protoError{codeBadSig, "bad sig encoding"}
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(payload), sig) {
		return &protoError{codeBadSig, "verification failed"}
	}
	return nil
}

// tsFresh reports whether ts is inside the ±300 s window.
func tsFresh(ts int64) bool {
	drift := nowMS() - ts
	if drift < 0 {
		drift = -drift
	}
	return drift <= tsWindow
}

// nonceCache remembers hello nonces per pubkey for the replay window.
type nonceCache struct {
	mu   sync.Mutex
	seen map[string]map[string]time.Time // pubkey → nonce → expiry
}

func newNonceCache() *nonceCache {
	return &nonceCache{seen: map[string]map[string]time.Time{}}
}

// check records a nonce; false means it was already seen (replay).
func (n *nonceCache) check(pub, nonce string, now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	perPub := n.seen[pub]
	if perPub == nil {
		perPub = map[string]time.Time{}
		n.seen[pub] = perPub
	}
	if exp, ok := perPub[nonce]; ok && now.Before(exp) {
		return false
	}
	perPub[nonce] = now.Add(replayKeep)
	for k, exp := range perPub {
		if !now.Before(exp) {
			delete(perPub, k)
		}
	}
	return true
}

// handleHello authenticates the first frame on a connection.
func (h *hub) handleHello(cl *client, f frame, raw map[string]any) {
	if cl.authed {
		h.sendErr(cl, codeBadFrame, "already authenticated")
		return
	}
	if perr := h.checkHello(f, raw); perr != nil {
		h.reject(cl, perr.code, perr.msg)
		return
	}
	h.welcome(cl, f)
}

// reject answers a failed hello synchronously (direct write, bypassing
// the pump) so the error frame reaches the peer before the close.
func (h *hub) reject(cl *client, code, msg string) {
	b, err := json.Marshal(frame{Op: "error", Code: code, Msg: msg})
	if err != nil {
		cl.drop()
		return
	}
	h.log.Printf("conn=%s code=%s msg=%s", cl.agentID, code, msg)
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	cl.conn.Write(ctx, websocket.MessageText, b)
	cl.drop()
}

// checkHello runs the full auth gauntlet: signature, timestamp, nonce.
func (h *hub) checkHello(f frame, raw map[string]any) *protoError {
	if len(f.Nonce) < nonceMinLen {
		return &protoError{codeBadFrame, "nonce too short"}
	}
	if perr := verifySignature(f, raw, f.Pubkey); perr != nil {
		return perr
	}
	if !tsFresh(f.TS) {
		return &protoError{codeStaleTS, "timestamp outside ±300s window"}
	}
	if !h.nonces.check(f.Pubkey, f.Nonce, time.Now()) {
		return &protoError{codeReplay, "nonce already used"}
	}
	return nil
}

// welcome installs the authenticated client, evicting any previous
// connection for the same agentId.
func (h *hub) welcome(cl *client, f frame) {
	pub, _ := base64.StdEncoding.DecodeString(f.Pubkey)
	cl.agentID = agentIDFor(pub)
	cl.pubkey = f.Pubkey
	cl.x25519 = f.X25519
	cl.name = f.Name
	cl.authed = true
	h.register(cl)
	cl.sendFrame(frame{Op: "welcome", AgentID: cl.agentID, ResumeToken: newToken()})
}

// newToken returns a random hex resume token.
func newToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
