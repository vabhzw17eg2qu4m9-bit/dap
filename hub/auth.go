package main

// auth.go — hello handshake, Ed25519 envelope verification, replay cache.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"
)

const (
	tsWindow        = 300_000                                                // ms, spec: ±300 s
	replayKeep      = time.Duration(tsWindow)*time.Millisecond + time.Minute // cover the full ts window
	nonceSweepEvery = time.Minute
	nonceMinLen     = 16
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
	mu        sync.Mutex
	seen      map[string]map[string]time.Time // pubkey → nonce → expiry
	lastSweep time.Time
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
	if now.Sub(n.lastSweep) >= nonceSweepEvery {
		n.sweepLocked(now)
	}
	return true
}

// sweepLocked drops expired nonces and pubkeys with no live nonces.
func (n *nonceCache) sweepLocked(now time.Time) {
	n.lastSweep = now
	for pub, perPub := range n.seen {
		for nonce, exp := range perPub {
			if !now.Before(exp) {
				delete(perPub, nonce)
			}
		}
		if len(perPub) == 0 {
			delete(n.seen, pub)
		}
	}
}

// sendIDCache is a bounded per-sender FIFO of ACCEPTED send-frame ids.
// Membership (seen) never latches — ids latch only after the routing
// decision succeeds, so a frame rejected for membership/ACL/unknown-agent
// can be retried with the same id. The cap bounds memory against a
// high-rate sender; the dedupe window is therefore "last sendIDCap accepted
// sends", an approximation that is a safety net against client id reuse,
// not a cryptographic guarantee.
const sendIDCap = 4096

type sendIDCache struct {
	mu   sync.Mutex
	ids  map[string][]string // pubkey → ring buffer of recent ids
	next map[string]int      // pubkey → next overwrite index (once full)
}

func newSendIDCache() *sendIDCache {
	return &sendIDCache{ids: map[string][]string{}, next: map[string]int{}}
}

// seen reports whether pub already sent id (no side effects).
func (s *sendIDCache) seen(pub, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.ids[pub] {
		if v == id {
			return true
		}
	}
	return false
}

// add latches id for pub, overwriting the oldest entry once the cap is hit.
func (s *sendIDCache) add(pub, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ring := s.ids[pub]
	if len(ring) < sendIDCap {
		s.ids[pub] = append(ring, id)
		return
	}
	ring[s.next[pub]] = id
	s.next[pub] = (s.next[pub] + 1) % sendIDCap
}

// handleHello authenticates the first frame on a connection.
func (h *hub) handleHello(cl *client, f frame, raw map[string]any) {
	// Derive the id from the (still unverified) hello pubkey so trace
	// lines can name the agent even when authentication fails.
	if pub, err := base64.StdEncoding.DecodeString(f.Pubkey); err == nil {
		cl.helloID = agentIDFor(pub)
	}
	h.logf("hello", "agent", cl.logAgent(), "name", f.Name)
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

// reject answers a failed hello through the write pump (single writer);
// the pump writes the frame, then drops the connection.
func (h *hub) reject(cl *client, code, msg string) {
	b, err := json.Marshal(frame{Op: "error", Code: code, Msg: msg})
	if err != nil {
		cl.drop()
		return
	}
	cl.errCode = code
	// traced before the error frame is queued for the pump
	h.logf("auth_fail", "agent", cl.logAgent(), "code", code, "msg", msg)
	select {
	case cl.rejectCh <- b:
		// wait for the pump to write the frame and drop the conn, so
		// the caller's deregister cannot close before the error lands
		<-cl.closed
	case <-cl.closed:
	}
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
	cl.sendFrame(frame{Op: "welcome", AgentID: cl.agentID})
}
