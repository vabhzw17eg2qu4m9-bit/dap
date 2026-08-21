package main

// mailbox.go — bounded offline mailbox (cap 100, drop oldest) + flush.

const mailboxCap = 100

// enqueue buffers a message for an offline agent. On overflow the oldest
// entry is dropped and the mailbox_full flag latches until the next flush.
func (h *hub) enqueue(agentID string, f frame) {
	h.mu.Lock()
	defer h.mu.Unlock()
	q := append(h.mailbox[agentID], f)
	if len(q) > mailboxCap {
		q = q[len(q)-mailboxCap:]
		h.mailboxDropped[agentID] = true
	}
	h.mailbox[agentID] = q
}

// drain empties the mailbox, reporting whether overflow happened.
func (h *hub) drain(agentID string) ([]frame, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	q := h.mailbox[agentID]
	dropped := h.mailboxDropped[agentID]
	delete(h.mailbox, agentID)
	delete(h.mailboxDropped, agentID)
	return q, dropped
}

// handleFlush streams queued messages in order, reports mailbox_full at
// most once per overflow episode, then confirms with a count.
func (h *hub) handleFlush(cl *client, _ frame, _ map[string]any) {
	msgs, dropped := h.drain(cl.agentID)
	for _, m := range msgs {
		cl.sendFrame(m)
	}
	if dropped {
		h.sendErr(cl, codeMailboxFull, "mailbox overflowed; oldest messages dropped")
	}
	cl.sendFrame(frame{Op: "flushed", Count: len(msgs)})
}
