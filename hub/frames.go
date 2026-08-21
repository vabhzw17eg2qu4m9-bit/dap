package main

// frames.go — DAP/1 wire frame types and parsing.

import (
	"bytes"
	"encoding/json"
)

// Error codes from the DAP/1 spec.
const (
	codeBadSig         = "bad_signature"
	codeStaleTS        = "stale_ts"
	codeReplay         = "replayed_nonce"
	codeNotAuth        = "not_authenticated"
	codeDenied         = "access_denied"
	codeUnknownChannel = "unknown_channel"
	codeUnknownAgent   = "unknown_agent"
	codeMailboxFull    = "mailbox_full"
	codeBadFrame       = "bad_frame"
)

// agentInfo is one entry of a presence list.
type agentInfo struct {
	AgentID  string `json:"agentId"`
	Pubkey   string `json:"pubkey"`
	X25519   string `json:"x25519,omitempty"`
	Name     string `json:"name,omitempty"`
	Online   bool   `json:"online"`
	LastSeen int64  `json:"lastSeen,omitempty"`
}

// frame is the union of every DAP/1 frame. Hub→client frames are
// marshaled from it; client→hub frames are parsed into it. Signature
// verification always uses the raw map (see auth.go), never this struct.
type frame struct {
	Op         string      `json:"op"`
	V          int         `json:"v,omitempty"`
	Pubkey     string      `json:"pubkey,omitempty"`
	X25519     string      `json:"x25519,omitempty"`
	Name       string      `json:"name,omitempty"`
	Nonce      string      `json:"nonce,omitempty"`
	TS         int64       `json:"ts,omitempty"`
	Sig        string      `json:"sig,omitempty"`
	AgentID    string      `json:"agentId,omitempty"`
	Online     *bool       `json:"online,omitempty"`
	LastSeen   int64       `json:"lastSeen,omitempty"`
	Channel    string      `json:"channel,omitempty"`
	ChanPubkey string      `json:"chanPubkey,omitempty"`
	To         string      `json:"to,omitempty"`
	From       string      `json:"from,omitempty"`
	ID         string      `json:"id,omitempty"`
	Ciphertext string      `json:"ciphertext,omitempty"`
	Count      int         `json:"count,omitempty"`
	Agents     []agentInfo `json:"agents,omitempty"`
	Code       string      `json:"code,omitempty"`
	Msg        string      `json:"msg,omitempty"`
}

// protoError is an error carrying a spec error code.
type protoError struct {
	code string
	msg  string
}

func (e *protoError) Error() string { return e.code + ": " + e.msg }

// parseFrame decodes one wire frame into the typed view plus the raw
// object map used for signature canonicalization.
func parseFrame(data []byte) (frame, map[string]any, error) {
	var f frame
	if err := json.Unmarshal(data, &f); err != nil {
		return f, nil, err
	}
	raw, err := decodeRaw(data)
	return f, raw, err
}

// decodeRaw decodes JSON preserving number literals so that
// re-canonicalization reproduces the bytes the peer signed.
func decodeRaw(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	m := map[string]any{}
	err := dec.Decode(&m)
	return m, err
}
