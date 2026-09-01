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

// adminEvict removes one agent's identity from the registry: an explicit
// owner action (the registry is never pruned by TTL — see lookupAgent).
// Online agents are refused; they must disconnect first. The agent's
// queued mailbox frames go with the identity — they are undeliverable
// once it is gone.
func (h *hub) adminEvict(w http.ResponseWriter, r *http.Request) {
	if !h.adminOK(w, r) {
		return
	}
	id := r.PathValue("agentId")
	h.mu.Lock()
	switch {
	case h.agents[id] == nil:
		h.mu.Unlock()
		http.Error(w, "no such agent", http.StatusNotFound)
		return
	case h.clients[id] != nil:
		h.mu.Unlock()
		http.Error(w, "agent is online", http.StatusConflict)
		return
	}
	name := h.agents[id].Name
	delete(h.agents, id)
	delete(h.mailbox, id)
	delete(h.mailboxDropped, id)
	// The issued secret is keyed by hello NAME, and duplicate enrollments
	// can share one name. Purge it only when this eviction took the last
	// registry entry holding the name; otherwise the surviving agent's
	// dial-in would break.
	_, held := h.secrets[name]
	shared := false
	for _, e := range h.agents {
		if e.Name == name {
			shared = true
			break
		}
	}
	switch {
	case held && shared:
		h.logf("admin", "action", "evict", "agent", id, "name", name, "secret_purge", "skipped", "reason", "name still held by another agent")
	case held:
		delete(h.secrets, name)
		h.persistSecrets()
	}
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
	h.logf("admin", "method", r.Method, "path", r.URL.Path, "result", "ok", "action", "evict", "agent", id)
}
