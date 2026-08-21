package main

// relay.go — connection registry, one-conn-per-agent eviction, ping loop,
// frame dispatch. Port of the yoloit-hub relay pattern.

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	maxFrameBytes = 1 << 20
	sendBuffer    = 512
	writeTimeout  = 10 * time.Second
	pingEvery     = 30 * time.Second
)

// agentEntry is the durable identity record (survives disconnects).
type agentEntry struct {
	Pubkey   string
	X25519   string
	Name     string
	Online   bool
	LastSeen int64
}

// client is one live WebSocket connection.
type client struct {
	h         *hub
	conn      *websocket.Conn
	send      chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	authed    bool
	agentID   string
	pubkey    string
	x25519    string
	name      string
}

// handlerFunc handles one authenticated client op (hello included).
type handlerFunc func(*client, frame, map[string]any)

// hub is the whole server state. It stores ciphertext only.
type hub struct {
	mu             sync.RWMutex
	clients        map[string]*client
	agents         map[string]*agentEntry
	channels       map[string]*channel
	mailbox        map[string][]frame
	mailboxDropped map[string]bool
	nonces         *nonceCache
	handlers       map[string]handlerFunc
	adminToken     string
	storePath      string
	log            *log.Logger
	pingEvery      time.Duration
}

func newHub(adminToken, storePath string, logOut io.Writer) *hub {
	h := &hub{
		clients:        map[string]*client{},
		agents:         map[string]*agentEntry{},
		channels:       map[string]*channel{},
		mailbox:        map[string][]frame{},
		mailboxDropped: map[string]bool{},
		nonces:         newNonceCache(),
		adminToken:     adminToken,
		storePath:      storePath,
		log:            log.New(logOut, "", log.LstdFlags|log.Lmicroseconds),
		pingEvery:      pingEvery,
	}
	h.handlers = map[string]handlerFunc{
		"hello":          h.handleHello,
		"whois":          h.handleWhois,
		"presence_query": h.handlePresenceQuery,
		"join":           h.handleJoin,
		"send":           h.handleSend,
		"flush":          h.handleFlush,
	}
	return h
}

// handleWS upgrades, then runs the read loop for the connection's life.
func (h *hub) handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(2 * maxFrameBytes) // hard DoS cap; protocol check below
	cl := &client{h: h, conn: c, send: make(chan []byte, sendBuffer), closed: make(chan struct{})}
	go h.writePump(cl)
	h.readLoop(cl, r.Context())
	h.deregister(cl)
}

// readLoop reads, parses and dispatches frames until the connection dies.
func (h *hub) readLoop(cl *client, ctx context.Context) {
	for {
		typ, rd, err := cl.conn.Reader(ctx)
		if err != nil {
			return
		}
		data, err := io.ReadAll(rd) // full message, bounded by read limit
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			h.sendErr(cl, codeBadFrame, "text frames only")
			continue
		}
		if len(data) > maxFrameBytes {
			h.reject(cl, codeBadFrame, "frame too large")
			return
		}
		h.dispatch(cl, data)
	}
}

// dispatch routes one raw frame to its handler.
func (h *hub) dispatch(cl *client, data []byte) {
	f, raw, err := parseFrame(data)
	if err != nil {
		h.sendErr(cl, codeBadFrame, err.Error())
		return
	}
	if !cl.authed && f.Op != "hello" {
		h.sendErr(cl, codeNotAuth, "send hello first")
		return
	}
	if fn, ok := h.handlers[f.Op]; ok {
		fn(cl, f, raw)
		return
	}
	h.sendErr(cl, codeBadFrame, "unknown op "+f.Op)
}

// writePump serializes writes and pings the peer every pingEvery.
func (h *hub) writePump(c *client) {
	ticker := time.NewTicker(h.pingEvery)
	defer ticker.Stop()
	for {
		select {
		case b := <-c.send:
			if !c.write(b) {
				return
			}
		case <-ticker.C:
			if !c.ping() {
				return
			}
		case <-c.closed:
			return
		}
	}
}

// write sends one text frame; false means the connection is gone.
func (c *client) write(b []byte) bool {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	return c.conn.Write(ctx, websocket.MessageText, b) == nil
}

// ping sends a WebSocket control ping; false means the connection is gone.
func (c *client) ping() bool {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	return c.conn.Ping(ctx) == nil
}

// drop idempotently terminates the connection (eviction, error, EOF).
func (c *client) drop() {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.conn.CloseNow()
	})
}

// sendFrame queues a frame for the write pump; false if dropped.
func (c *client) sendFrame(f frame) bool {
	b, err := json.Marshal(f)
	if err != nil {
		return false
	}
	select {
	case c.send <- b:
		return true
	case <-c.closed:
		return false
	}
}

// sendErr emits a spec error frame (codes from frames.go).
func (h *hub) sendErr(cl *client, code, msg string) {
	h.log.Printf("conn=%s code=%s msg=%s", cl.agentID, code, msg)
	cl.sendFrame(frame{Op: "error", Code: code, Msg: msg})
}

// register installs an authenticated client, evicting any previous
// connection held by the same agentId, then announces presence.
func (h *hub) register(cl *client) {
	h.mu.Lock()
	if old, ok := h.clients[cl.agentID]; ok && old != cl {
		old.drop()
	}
	h.clients[cl.agentID] = cl
	e := h.upsertAgentLocked(cl)
	peers := h.presencePeersLocked(cl.agentID)
	h.mu.Unlock()
	h.sendPresence(peers, cl.agentID, e.Name, e.X25519, e.Pubkey, true)
}

// deregister removes a dead client unless a newer connection replaced it.
func (h *hub) deregister(cl *client) {
	cl.drop()
	h.mu.Lock()
	if h.clients[cl.agentID] != cl {
		h.mu.Unlock()
		return
	}
	delete(h.clients, cl.agentID)
	e := h.agents[cl.agentID]
	e.Online = false
	e.LastSeen = nowMS()
	peers := h.presencePeersLocked(cl.agentID)
	h.mu.Unlock()
	h.sendPresence(peers, cl.agentID, e.Name, e.X25519, e.Pubkey, false)
}

// upsertAgentLocked creates or refreshes the identity record.
// Caller holds h.mu.
func (h *hub) upsertAgentLocked(cl *client) *agentEntry {
	e := h.agents[cl.agentID]
	if e == nil {
		e = &agentEntry{}
		h.agents[cl.agentID] = e
	}
	e.Pubkey = cl.pubkey
	e.X25519 = cl.x25519
	e.Name = cl.name
	e.Online = true
	e.LastSeen = nowMS()
	return e
}

// lookupAgent returns a copy of the identity record, or nil.
func (h *hub) lookupAgent(agentID string) *agentEntry {
	h.mu.RLock()
	defer h.mu.RUnlock()
	e := h.agents[agentID]
	if e == nil {
		return nil
	}
	cp := *e
	return &cp
}

// presencePeersLocked lists connected members sharing any channel with
// agentID (the agent itself excluded). Caller holds h.mu.
func (h *hub) presencePeersLocked(agentID string) []*client {
	seen := map[*client]bool{}
	for _, ch := range h.channels {
		if !ch.Members[agentID] {
			continue
		}
		for memberID := range ch.Members {
			if c := h.clients[memberID]; c != nil && memberID != agentID {
				seen[c] = true
			}
		}
	}
	peers := make([]*client, 0, len(seen))
	for c := range seen {
		peers = append(peers, c)
	}
	return peers
}

func nowMS() int64 { return time.Now().UnixMilli() }
