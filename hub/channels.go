package main

// channels.go — channel registry, pubkey ACLs, message routing.
// The hub stores and forwards ciphertext only.

// channel is a chat channel. Pubkey is the channel public key (b64)
// registered by the creator; members' clients hold the private key
// out-of-band. Allowed is the ACL (empty = any authenticated agent).
type channel struct {
	Name    string
	Pubkey  string
	Allowed []string
	Members map[string]bool // agentIds ever joined (in-memory, v1)
}

// allows checks the ACL with constant-time pubkey comparison.
func (ch *channel) allows(pubkey string) bool {
	if len(ch.Allowed) == 0 {
		return true
	}
	for _, allowed := range ch.Allowed {
		if constEq(allowed, pubkey) {
			return true
		}
	}
	return false
}

// handleJoin adds the sender to a channel, creating it on first join
// (the creator registers the channel public key).
func (h *hub) handleJoin(cl *client, f frame, _ map[string]any) {
	if f.Channel == "" {
		h.sendErr(cl, codeBadFrame, "join requires channel")
		return
	}
	if perr := h.joinChannel(cl, f.Channel, f.ChanPubkey); perr != nil {
		h.sendErr(cl, perr.code, perr.msg)
		return
	}
	cl.sendFrame(frame{Op: "joined", Channel: f.Channel})
}

// joinChannel creates or fetches the channel and adds the agent as a
// member, enforcing the ACL.
func (h *hub) joinChannel(cl *client, name, chanPub string) *protoError {
	created, rejoin := false, false
	h.mu.Lock()
	ch := h.channels[name]
	if ch == nil {
		ch = h.newChannelLocked(name, chanPub)
		created = true
	}
	if !ch.allows(cl.pubkey) {
		h.mu.Unlock()
		h.logf("join", "agent", cl.logAgent(), "channel", dash(name), "result", "denied")
		return &protoError{codeDenied, "pubkey not on channel ACL"}
	}
	_, rejoin = ch.Members[cl.agentID]
	ch.Members[cl.agentID] = true
	peers := h.presencePeersLocked(cl.agentID)
	h.mu.Unlock()
	h.sendPresence(peers, cl.agentID, cl.name, cl.x25519, cl.pubkey, true)
	result := "joined"
	if created {
		result = "created"
	} else if rejoin {
		result = "rejoin"
	}
	h.logf("join", "agent", cl.logAgent(), "channel", name, "result", result)
	return nil
}

// newChannelLocked creates a channel and persists the registry.
// Caller holds h.mu.
func (h *hub) newChannelLocked(name, chanPub string) *channel {
	ch := &channel{Name: name, Pubkey: chanPub, Members: map[string]bool{}}
	h.channels[name] = ch
	h.persistChannels()
	return ch
}

// handleSend verifies the envelope signature and routes to DM or channel.
func (h *hub) handleSend(cl *client, f frame, raw map[string]any) {
	if perr := verifySignature(f, raw, cl.pubkey); perr != nil {
		h.sendErr(cl, perr.code, perr.msg)
		return
	}
	if !tsFresh(f.TS) {
		h.sendErr(cl, codeStaleTS, "timestamp outside ±300s window")
		return
	}
	if f.ID == "" {
		h.sendErr(cl, codeBadFrame, "send requires id")
		return
	}
	// Dedupe is latch-after-accept: a frame rejected for membership/ACL/
	// unknown-agent must NOT burn its id — clients retry the same id after
	// fixing the cause (joining, waiting for the peer), and ids are the
	// idempotency mechanism. The per-sender send-id cache is bounded; a
	// duplicate within the window is codeReplay.
	key := f.To + "|" + f.Channel + "|" + f.ID
	if h.sendIDs.seen(cl.pubkey, key) {
		h.sendErr(cl, codeReplay, "frame id already used")
		return
	}
	if f.To != "" {
		if !h.deliverDM(cl, f) {
			return
		}
	} else if !h.deliverChannel(cl, f) {
		return
	}
	h.sendIDs.add(cl.pubkey, key)
}

// deliverChannel fans a channel message out to connected members and
// enqueues it into offline members' mailboxes. Returns false when rejected.
func (h *hub) deliverChannel(cl *client, f frame) bool {
	msg, online, offline, perr := h.channelTargets(cl, f)
	if perr != nil {
		h.logf("chan", "agent", cl.logAgent(), "channel", dash(f.Channel), "result", "denied", "code", perr.code)
		h.sendErr(cl, perr.code, perr.msg)
		return false
	}
	for _, c := range online {
		c.sendFrame(msg)
	}
	for _, agentID := range offline {
		h.enqueue(agentID, msg)
	}
	h.logf("chan", "agent", cl.logAgent(), "channel", f.Channel, "result", "ok",
		"fanout", len(online)+len(offline), "online", len(online), "offline", len(offline))
	return true
}

// channelTargets resolves recipients under h.mu.
func (h *hub) channelTargets(cl *client, f frame) (frame, []*client, []string, *protoError) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ch := h.channels[f.Channel]
	if ch == nil {
		return frame{}, nil, nil, &protoError{codeUnknownChannel, "no such channel: " + f.Channel}
	}
	if !ch.Members[cl.agentID] {
		return frame{}, nil, nil, &protoError{codeDenied, "not a member: join the channel first"}
	}
	if !ch.allows(cl.pubkey) {
		return frame{}, nil, nil, &protoError{codeDenied, "pubkey not on channel ACL"}
	}
	msg := frame{Op: "msg", Channel: f.Channel, From: cl.agentID, ID: f.ID, TS: f.TS, Ciphertext: f.Ciphertext}
	var online []*client
	var offline []string
	for memberID := range ch.Members {
		if c := h.clients[memberID]; c != nil {
			online = append(online, c)
		} else {
			offline = append(offline, memberID)
		}
	}
	return msg, online, offline, nil
}

// deliverDM hands a direct message to the recipient — or their mailbox.
// The sender never receives an echo (spec). Returns false when rejected.
func (h *hub) deliverDM(cl *client, f frame) bool {
	msg := frame{Op: "msg", To: f.To, From: cl.agentID, ID: f.ID, TS: f.TS, Ciphertext: f.Ciphertext}
	if h.lookupAgent(f.To) == nil {
		h.logf("dm", "agent", cl.logAgent(), "to", dash(f.To), "result", "unknown")
		h.sendErr(cl, codeUnknownAgent, "no such agent: "+f.To)
		return false
	}
	h.mu.RLock()
	rec := h.clients[f.To]
	h.mu.RUnlock()
	if rec == nil {
		size := h.enqueue(f.To, msg)
		h.logf("dm", "agent", cl.logAgent(), "to", f.To, "result", "mailbox", "size", size)
		return true
	}
	if !rec.sendFrame(msg) {
		h.logf("dm", "agent", cl.logAgent(), "to", f.To, "result", "dropped")
		return true
	}
	h.logf("dm", "agent", cl.logAgent(), "to", f.To, "result", "online")
	return true
}
