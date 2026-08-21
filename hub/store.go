package main

// store.go — atomic (tmp + rename) JSON persistence of the channel registry.

import (
	"encoding/json"
	"os"
)

// channelRecord is the on-disk shape of one channel.
type channelRecord struct {
	Name    string   `json:"name"`
	Pubkey  string   `json:"pubkey,omitempty"`
	Allowed []string `json:"allowed,omitempty"`
}

type channelStore struct {
	Channels []channelRecord `json:"channels"`
}

// persistChannels writes channels.json atomically. Caller holds h.mu.
func (h *hub) persistChannels() {
	records := make([]channelRecord, 0, len(h.channels))
	for name, ch := range h.channels {
		records = append(records, channelRecord{Name: name, Pubkey: ch.Pubkey, Allowed: ch.Allowed})
	}
	if err := writeAtomic(h.storePath, channelStore{Channels: records}); err != nil {
		h.log.Printf("store: write %s failed: %v", h.storePath, err)
	}
}

// writeAtomic marshals v, writes a tmp file beside path, then renames.
func writeAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadChannels restores the channel registry from disk. A missing file
// is not an error (first boot).
func (h *hub) loadChannels() {
	b, err := os.ReadFile(h.storePath)
	if err != nil {
		return
	}
	var cs channelStore
	if err := json.Unmarshal(b, &cs); err != nil {
		h.log.Printf("store: parse %s failed: %v", h.storePath, err)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, rec := range cs.Channels {
		h.channels[rec.Name] = &channel{Name: rec.Name, Pubkey: rec.Pubkey, Allowed: rec.Allowed, Members: map[string]bool{}}
	}
}
