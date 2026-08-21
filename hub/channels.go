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
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := h.channels[name]
	if ch == nil {
		ch = h.newChannelLocked(name, chanPub)
	}
	if !ch.allows(cl.pubkey) {
		return &protoError{codeDenied, "pubkey not on channel ACL"}
	}
	ch.Members[cl.agentID] = true
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
	if f.To != "" {
		h.deliverDM(cl, f)
		return
	}
	h.deliverChannel(cl, f)
}

// deliverChannel fans a channel message out to connected members and
// enqueues it into offline members' mailboxes.
func (h *hub) deliverChannel(cl *client, f frame) {
	msg, online, offline, perr := h.channelTargets(cl, f)
	if perr != nil {
		h.sendErr(cl, perr.code, perr.msg)
		return
	}
	for _, c := range online {
		c.sendFrame(msg)
	}
	for _, agentID := range offline {
		h.enqueue(agentID, msg)
	}
}

// channelTargets resolves recipients under h.mu.
func (h *hub) channelTargets(cl *client, f frame) (frame, []*client, []string, *protoError) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ch := h.channels[f.Channel]
	if ch == nil {
		return frame{}, nil, nil, &protoError{codeUnknownChannel, "no such channel: " + f.Channel}
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
// The sender never receives an echo (spec).
func (h *hub) deliverDM(cl *client, f frame) {
	msg := frame{Op: "msg", To: f.To, From: cl.agentID, ID: f.ID, TS: f.TS, Ciphertext: f.Ciphertext}
	if h.lookupAgent(f.To) == nil {
		h.sendErr(cl, codeUnknownAgent, "no such agent: "+f.To)
		return
	}
	h.mu.RLock()
	rec := h.clients[f.To]
	h.mu.RUnlock()
	if rec == nil {
		h.enqueue(f.To, msg)
		return
	}
	rec.sendFrame(msg)
}
