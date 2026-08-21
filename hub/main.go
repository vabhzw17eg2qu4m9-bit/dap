package main

// main.go — config, routing table, server bootstrap.

import (
	"flag"
	"log"
	"net/http"
	"os"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// buildMux wires every DAP/1 endpoint.
func buildMux(h *hub) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/ws", h.handleWS)
	mux.HandleFunc("GET /api/channels", h.adminChannels)
	mux.HandleFunc("PUT /api/channels/{name}/acl", h.adminSetACL)
	mux.HandleFunc("GET /api/agents", h.adminAgents)
	return mux
}

func run(addr, adminToken, storePath string) error {
	h := newHub(adminToken, storePath, os.Stderr)
	h.loadChannels()
	srv := &http.Server{Addr: addr, Handler: buildMux(h)}
	log.Printf("dap-hub listening on %s", addr)
	return srv.ListenAndServe()
}

func main() {
	addr := flag.String("addr", envOr("HUB_ADDR", ":8080"), "listen address")
	adminToken := flag.String("admin-token", os.Getenv("HUB_ADMIN_TOKEN"), "admin API bearer token (env HUB_ADMIN_TOKEN)")
	storePath := flag.String("channels-file", envOr("HUB_CHANNELS_FILE", "channels.json"), "channel registry path (env HUB_CHANNELS_FILE)")
	flag.Parse()
	if err := run(*addr, *adminToken, *storePath); err != nil {
		log.Fatal(err)
	}
}
