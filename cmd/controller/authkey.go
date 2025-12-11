package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// GlobalAuth manages a single shared auth key for all nodes.
type GlobalAuth struct {
	mu   sync.Mutex
	key  string
	file string
}

func NewGlobalAuth(path string) *GlobalAuth {
	return &GlobalAuth{file: path}
}

func (g *GlobalAuth) LoadOrCreate() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.key != "" {
		return g.key
	}
	if data, err := os.ReadFile(g.file); err == nil {
		key := strings.TrimSpace(string(data))
		if key != "" {
			g.key = key
			return g.key
		}
	}
	key := randomKey()
	if err := os.MkdirAll(filepath.Dir(g.file), 0o755); err != nil {
		log.Printf("failed to create auth key dir: %v", err)
	} else if err := os.WriteFile(g.file, []byte(key), 0o600); err != nil {
		log.Printf("failed to write auth key: %v", err)
	}
	g.key = key
	return g.key
}
