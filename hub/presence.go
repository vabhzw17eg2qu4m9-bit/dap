package main

// presence.go — whois directory and presence query/broadcast.

// handleWhois answers with the target agent's public identity.
func (h *hub) handleWhois(cl *client, f frame, _ map[string]any) {
	e := h.lookupAgent(f.AgentID)
	if e == nil {
		h.sendErr(cl, codeUnknownAgent, "no such agent: "+f.AgentID)
		return
	}
	cl.sendFrame(frame{Op: "agent_info", AgentID: f.AgentID, Pubkey: e.Pubkey, X25519: e.X25519, Name: e.Name, Online: &e.Online, LastSeen: e.LastSeen})
}

// handlePresenceQuery lists every known agent with online state.
func (h *hub) handlePresenceQuery(cl *client, _ frame, _ map[string]any) {
	cl.sendFrame(frame{Op: "presence", Agents: h.presenceList()})
}

// presenceList snapshots the agent registry (no pruning — see lookupAgent).
func (h *hub) presenceList() []agentInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()
	list := make([]agentInfo, 0, len(h.agents))
	for id, e := range h.agents {
		list = append(list, agentInfo{AgentID: id, Pubkey: e.Pubkey, X25519: e.X25519, Name: e.Name, Online: e.Online, LastSeen: e.LastSeen})
	}
	return list
}

// sendPresence announces one agent's state change to the given peers
// (connected members sharing a channel with the agent).
func (h *hub) sendPresence(peers []*client, agentID, name, x25519, pubkey string, online bool) {
	if len(peers) == 0 {
		return
	}
	info := agentInfo{AgentID: agentID, Name: name, X25519: x25519, Pubkey: pubkey, Online: online, LastSeen: h.now()}
	f := frame{Op: "presence", Agents: []agentInfo{info}}
	for _, p := range peers {
		p.sendFrame(f)
	}
}
