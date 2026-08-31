package main

// relay.go — connection registry, one-conn-per-agent eviction, ping loop,
// frame dispatch. Port of the yoloit-hub relay pattern.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

const (
	maxFrameBytes  = 1 << 20
	sendBuffer     = 512
	maxQueuedBytes = 4 << 20 // per-client queued-bytes cap; overflow drops the conn
	writeTimeout   = 10 * time.Second
	pingEvery      = 30 * time.Second
)

// close reasons: why a WebSocket died, for the ws_close trace line.
const (
	closeUnknown int32 = iota
	closeEOF
	closeError
	closeEvicted
	closeWriteFail
	closePingTimeout
	closeBackpressure
)

var closeNames = map[int32]string{
	closeUnknown:      "error",
	closeEOF:          "eof",
	closeError:        "error",
	closeEvicted:      "evicted",
	closeWriteFail:    "write_fail",
	closePingTimeout:  "ping_timeout",
	closeBackpressure: "backpressure",
}

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
	rejectCh  chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	queued    atomic.Int64
	reason    atomic.Int32 // first close cause wins (ws_close trace)
	authed    bool
	agentID   string
	pubkey    string
	x25519    string
	name      string
	auth      authKind // set at the upgrade: master or issued-secret agent
	boundName string   // authAgent only: the name the secret is bound to
	// errCode is the error code sent for the op currently being
	// dispatched; touched only by this client's read-loop goroutine.
	errCode string
	// helloID is the agentId derived from an unverified hello pubkey so
	// pre-auth trace lines can name the agent; read-loop goroutine only.
	helloID string
}

// closedAs records the first cause of connection death.
func (c *client) closedAs(reason int32) { c.reason.CompareAndSwap(closeUnknown, reason) }

// closeBecauseRead classifies a terminal read error for the trace.
func (c *client) closeBecauseRead(err error) {
	if errors.Is(err, io.EOF) {
		c.closedAs(closeEOF)
		return
	}
	c.closedAs(closeError)
}

// logAgent names the agent on trace lines: authenticated id, else the id
// derived from the hello pubkey, else "-".
func (c *client) logAgent() string {
	if c.agentID != "" {
		return c.agentID
	}
	return dash(c.helloID)
}

// dash keeps key=value lines rectangular: empty values print as "-".
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// logf writes one trace line: "<event> key=val ...". Metadata only —
// ciphertext, keys and payloads must never be passed in.
func (h *hub) logf(event string, kv ...any) {
	line := event
	for i := 0; i+1 < len(kv); i += 2 {
		line += fmt.Sprintf(" %v=%v", kv[i], kv[i+1])
	}
	h.log.Print(line)
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
	sendIDs        *sendIDCache
	handlers       map[string]handlerFunc
	adminToken     string
	masterSecret   string
	storePath      string
	secretsPath    string
	secrets        map[string]string // enrolled name → sha256 hex of issued secret
	log            *log.Logger
	now            func() int64
	pingEvery      time.Duration
}

func newHub(cfg hubConfig, logOut io.Writer) *hub {
	h := &hub{
		clients:        map[string]*client{},
		agents:         map[string]*agentEntry{},
		channels:       map[string]*channel{},
		mailbox:        map[string][]frame{},
		mailboxDropped: map[string]bool{},
		nonces:         newNonceCache(),
		sendIDs:        newSendIDCache(),
		adminToken:     cfg.AdminToken,
		masterSecret:   cfg.MasterSecret,
		storePath:      cfg.StorePath,
		secretsPath:    cfg.SecretsPath,
		secrets:        map[string]string{},
		log:            log.New(logOut, "", log.LstdFlags|log.Lmicroseconds),
		now:            func() int64 { return time.Now().UnixMilli() },
		pingEvery:      pingEvery,
	}
	h.handlers = map[string]handlerFunc{
		"hello":          h.handleHello,
		"whois":          h.handleWhois,
		"presence_query": h.handlePresenceQuery,
		"join":           h.handleJoin,
		"send":           h.handleSend,
		"flush":          h.handleFlush,
		"enroll":         h.handleEnroll,
	}
	return h
}

// handleWS upgrades, then runs the read loop for the connection's life.
func (h *hub) handleWS(w http.ResponseWriter, r *http.Request) {
	kind, bound, ok := h.wsAuth(w, r)
	if !ok {
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(2 * maxFrameBytes) // hard DoS cap; protocol check below
	cl := &client{h: h, conn: c, send: make(chan []byte, sendBuffer), rejectCh: make(chan []byte, 1), closed: make(chan struct{}), auth: kind, boundName: bound}
	h.logf("ws_open", "remote", r.RemoteAddr)
	go h.writePump(cl)
	h.readLoop(cl, r.Context())
	h.deregister(cl)
	h.logf("ws_close", "agent", cl.logAgent(), "reason", closeNames[cl.reason.Load()])
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
			cl.closeBecauseRead(err)
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
	cl.errCode = ""
	f, raw, err := parseFrame(data)
	if err != nil {
		h.sendErr(cl, codeBadFrame, err.Error())
		h.logOp(cl, "", "", codeBadFrame)
		return
	}
	op := frameOp(f, raw)
	if !cl.authed && op != "hello" {
		h.sendErr(cl, codeNotAuth, "send hello first")
		h.logOp(cl, op, f.ID, codeNotAuth)
		return
	}
	if fn, ok := h.handlers[op]; ok {
		fn(cl, f, raw)
		h.logOp(cl, op, f.ID, cl.errCode)
		return
	}
	h.sendErr(cl, codeBadFrame, "unknown op "+op)
	h.logOp(cl, op, f.ID, codeBadFrame)
}

// logOp traces one dispatched op frame and how routing ended.
func (h *hub) logOp(cl *client, op, id, code string) {
	outcome := "ok"
	if code != "" {
		outcome = "err"
	}
	h.logf("op", "agent", cl.logAgent(), "op", dash(op), "id", dash(id), "outcome", outcome, "code", dash(code))
}

// writePump serializes writes and pings the peer every pingEvery.
func (h *hub) writePump(c *client) {
	ticker := time.NewTicker(h.pingEvery)
	defer ticker.Stop()
	defer c.drop() // every pump exit terminates the conn (reject depends on it)
	for {
		select {
		case b := <-c.send:
			if !c.write(b) {
				c.closedAs(closeWriteFail)
				h.logf("write_fail", "agent", c.logAgent(), "queued", c.queued.Load())
				return
			}
			c.queued.Add(int64(-len(b)))
		case b := <-c.rejectCh:
			c.write(b) // single-writer guarantee; best effort
			c.drop()   // reject is always fatal
		case <-ticker.C:
			if !c.ping() {
				c.closedAs(closePingTimeout)
				h.logf("ping_timeout", "agent", c.logAgent())
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

// sendFrame queues a frame for the write pump; false if dropped. A closed
// connection must never accept a frame — checking c.closed BEFORE the
// select removes the race where both cases are ready and the frame is
// queued into a write pump that is already gone (logged online, lost).
// Accepts any marshalable reply shape (frame, enrolledReply).
func (c *client) sendFrame(f any) bool {
	b, err := json.Marshal(f)
	if err != nil {
		return false
	}
	if c.queued.Load()+int64(len(b)) > maxQueuedBytes {
		c.h.logf("backpressure", "agent", c.logAgent(), "queued", c.queued.Load())
		c.closedAs(closeBackpressure)
		c.drop() // slow consumer: shed it rather than buffer unbounded
		return false
	}
	c.queued.Add(int64(len(b)))
	select {
	case <-c.closed:
		c.queued.Add(int64(-len(b)))
		return false
	default:
	}
	select {
	case c.send <- b:
		return true
	case <-c.closed:
		c.queued.Add(int64(-len(b)))
		return false
	}
}

// sendErr emits a spec error frame (codes from frames.go).
func (h *hub) sendErr(cl *client, code, msg string) {
	cl.errCode = code
	h.logf("err", "agent", cl.logAgent(), "code", code, "msg", msg)
	cl.sendFrame(frame{Op: "error", Code: code, Msg: msg})
}

// register installs an authenticated client, evicting any previous
// connection held by the same agentId, then announces presence.
func (h *hub) register(cl *client) {
	h.mu.Lock()
	if old, ok := h.clients[cl.agentID]; ok && old != cl {
		old.closedAs(closeEvicted)
		old.drop()
		h.logf("evict", "agent", cl.agentID)
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
	e.LastSeen = h.now()
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
	e.LastSeen = h.now()
	return e
}

// lookupAgent returns a copy of the identity record, or nil.
//
// The registry is intentionally NOT pruned on lookup or by TTL: an offline
// agent must stay addressable (whois, DM→mailbox) for as long as the hub
// process lives. Memory is bounded by the number of distinct agents, not by
// traffic (each mailbox is capped separately). Identity deletion is a v2
// knob (persistence + explicit TTL), not something the delivery path does —
// pruning on lookup silently dropped the first DM to a long-offline agent.
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
