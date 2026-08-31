package main

// admin.go — admin REST API. Bearer token from HUB_ADMIN_TOKEN,
// verified with a constant-time compare.

import (
	"encoding/json"
	"net/http"
)

// adminOK checks the bearer token; on failure it writes the 401 itself.
func (h *hub) adminOK(w http.ResponseWriter, r *http.Request) bool {
	got := bearerToken(r)
	if got == "" || h.adminToken == "" || !constEq(got, h.adminToken) {
		h.logf("admin", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "result", "denied")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// channelSummary is the GET /api/channels row.
type channelSummary struct {
	Name    string `json:"name"`
	Members int    `json:"members"`
	ACLSize int    `json:"aclSize"`
}

// adminChannels lists channels with member and ACL sizes.
func (h *hub) adminChannels(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(w, r) {
		return
	}
	h.mu.RLock()
	rows := make([]channelSummary, 0, len(h.channels))
	for name, ch := range h.channels {
		rows = append(rows, channelSummary{Name: name, Members: len(ch.Members), ACLSize: len(ch.Allowed)})
	}
	h.mu.RUnlock()
	writeJSON(w, rows)
	h.logf("admin", "method", r.Method, "path", r.URL.Path, "result", "ok", "channels", len(rows))
}

// adminSetACL replaces a channel's ACL (upserting the channel).
func (h *hub) adminSetACL(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(w, r) {
		return
	}
	var body struct {
		Allowed []string `json:"allowed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.logf("admin", "method", r.Method, "path", r.URL.Path, "result", "bad_request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.setACL(r.PathValue("name"), body.Allowed)
	w.WriteHeader(http.StatusNoContent)
	h.logf("admin", "method", r.Method, "path", r.URL.Path, "result", "ok", "channel", r.PathValue("name"), "acl", len(body.Allowed))
}

// setACL upserts the channel and persists the registry.
func (h *hub) setACL(name string, allowed []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := h.channels[name]
	if ch == nil {
		ch = &channel{Name: name, Members: map[string]bool{}}
		h.channels[name] = ch
	}
	ch.Allowed = allowed
	h.persistChannels()
}

// adminAgents lists agent presence.
func (h *hub) adminAgents(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(w, r) {
		return
	}
	agents := h.presenceList()
	writeJSON(w, agents)
	h.logf("admin", "method", r.Method, "path", r.URL.Path, "result", "ok", "agents", len(agents))
}
