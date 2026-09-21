package main

// conn_scale_test.go — proves the ~1000-connection ceiling is the OS
// file-descriptor limit, not the hub: with the soft limit pinned at 1024
// dialing fails well below 1024 in-process connections, and with
// raiseFileLimit (what run() does at startup) 1100 concurrent
// authenticated connections work and deregister cleanly.
//
// Both subtests mutate the process-wide FD limit: NO t.Parallel() here.

import (
	"fmt"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestFDLimitIsThe1000ConnCeiling(t *testing.T) {
	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Setrlimit(syscall.RLIMIT_NOFILE, &orig) })
	if orig.Cur > 1024 {
		rl := orig
		rl.Cur = 1024
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
			t.Fatal(err)
		}
	}
	_, srv, _ := newTestHub(t)

	var conns []*websocket.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			c.CloseNow()
		}
	})
	var ok int
	var firstErr error
	for ok < 1024 {
		c, err := dialConn(t, srv)
		if err != nil {
			firstErr = err
			break
		}
		conns = append(conns, c)
		ok++
	}
	if firstErr == nil {
		t.Fatal("dialing never failed at soft NOFILE=1024; expected FD exhaustion")
	}
	if ok >= 1024 {
		t.Fatalf("%d connections succeeded at soft NOFILE=1024; ceiling should bind well below", ok)
	}
	t.Logf("first dial error after %d connections at soft NOFILE=1024: %v", ok, firstErr)
}

func TestBeyond1000ConcurrentConnections(t *testing.T) {
	soft, hard, raised, err := raiseFileLimit()
	if err != nil {
		t.Fatalf("raiseFileLimit: %v", err)
	}
	if hard < 2600 {
		t.Skipf("hard NOFILE %d < 2600: cannot hold 1100 in-process connections at 2 FDs each (soft=%d raised=%v)", hard, soft, raised)
	}
	h, srv, _ := newTestHub(t)

	const n = 1100
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	conns := make([]*websocket.Conn, 0, n)
	t.Cleanup(func() {
		for _, c := range conns {
			c.CloseNow()
		}
	})
	for i := 0; i < n; i++ {
		conns = append(conns, connect(t, srv, newAgent(t, fmt.Sprintf("scale-%04d", i))))
	}
	runtime.ReadMemStats(&after)
	t.Logf("heap bytes per connection: %d", (after.HeapAlloc-before.HeapAlloc)/n)

	h.mu.Lock()
	gotClients, gotAgents := len(h.clients), len(h.agents)
	h.mu.Unlock()
	if gotClients != n {
		t.Fatalf("hub holds %d clients, want %d", gotClients, n)
	}
	if gotAgents != n {
		t.Fatalf("hub holds %d agent identities, want %d", gotAgents, n)
	}

	for _, c := range conns {
		c.CloseNow()
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		h.mu.Lock()
		left := len(h.clients)
		h.mu.Unlock()
		if left == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("registry never drained: %d clients still registered after close", left)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
