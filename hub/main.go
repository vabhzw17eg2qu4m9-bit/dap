package main

// main.go — config, routing table, server bootstrap.

import (
	"errors"
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

// hubConfig is the startup configuration for one hub process.
type hubConfig struct {
	Addr         string
	AdminToken   string
	MasterSecret string
	StorePath    string
	SecretsPath  string
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
	mux.HandleFunc("DELETE /api/agents/{agentId}", h.adminEvict)
	return mux
}

func run(cfg hubConfig) error {
	if cfg.MasterSecret == "" {
		return errors.New("dap-hub: master secret is required: set -master-secret or HUB_MASTER_SECRET")
	}
	h := newHub(cfg, os.Stderr)
	h.loadChannels()
	h.loadSecrets()
	srv := &http.Server{Addr: cfg.Addr, Handler: buildMux(h)}
	log.Printf("dap-hub listening on %s", cfg.Addr)
	return srv.ListenAndServe()
}

func main() {
	addr := flag.String("addr", envOr("HUB_ADDR", ":8080"), "listen address")
	adminToken := flag.String("admin-token", os.Getenv("HUB_ADMIN_TOKEN"), "admin API bearer token (env HUB_ADMIN_TOKEN)")
	masterSecret := flag.String("master-secret", os.Getenv("HUB_MASTER_SECRET"), "master enrollment secret, required (env HUB_MASTER_SECRET)")
	storePath := flag.String("channels-file", envOr("HUB_CHANNELS_FILE", "channels.json"), "channel registry path (env HUB_CHANNELS_FILE)")
	secretsPath := flag.String("secrets-file", envOr("HUB_SECRETS_FILE", "secrets.json"), "issued client secret hashes path (env HUB_SECRETS_FILE)")
	flag.Parse()
	if err := run(hubConfig{
		Addr:         *addr,
		AdminToken:   *adminToken,
		MasterSecret: *masterSecret,
		StorePath:    *storePath,
		SecretsPath:  *secretsPath,
	}); err != nil {
		log.Fatal(err)
	}
}
