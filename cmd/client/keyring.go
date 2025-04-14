package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jadefox10200/zcomm/core"
)

type PublicKeyEntry struct {
	ID       string `json:"id"`
	EdPub    string `json:"ed_pub"`
	ECDHPub  string `json:"ecdh_pub"`
	Verified bool   `json:"verified"`
	AddedAt  int64  `json:"added_at"`
}

type KeyRing struct {
	mu       sync.RWMutex
	filepath string
	entries  map[string]PublicKeyEntry
}

func LoadKeyRing(path string) (*KeyRing, error) {
	kr := &KeyRing{
		filepath: path,
		entries:  make(map[string]PublicKeyEntry),
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return kr, nil // New empty keyring
		}
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&kr.entries); err != nil {
		return nil, err
	}
	return kr, nil
}

func (kr *KeyRing) SaveUnlocked(entries map[string]PublicKeyEntry) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(kr.filepath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	return os.WriteFile(kr.filepath, data, 0600)
}

func (kr *KeyRing) Save() error {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	// call unlocked save with a copy of entries
	entriesCopy := make(map[string]PublicKeyEntry, len(kr.entries))
	for k, v := range kr.entries {
		entriesCopy[k] = v
	}
	return kr.SaveUnlocked(entriesCopy)
}

func (kr *KeyRing) AddKey(entry PublicKeyEntry) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	existing, exists := kr.entries[entry.ID]
	if exists && existing.EdPub == entry.EdPub && existing.ECDHPub == entry.ECDHPub {
		return nil // Key already exists
	}

	entry.AddedAt = time.Now().Unix()
	kr.entries[entry.ID] = entry
	return kr.SaveUnlocked(kr.entries) // avoid locking inside Save
}

func (kr *KeyRing) GetKey(id string) (core.PublicKeys, bool) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	entry, ok := kr.entries[id]
	if !ok {
		return core.PublicKeys{}, false
	}
	return core.PublicKeys{
		EdPub:   entry.EdPub,
		ECDHPub: entry.ECDHPub,
	}, true
}

func (kr *KeyRing) AllKeys() []PublicKeyEntry {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	var list []PublicKeyEntry
	for _, v := range kr.entries {
		list = append(list, v)
	}
	return list
}

func (kr *KeyRing) VerifyKey(id string) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	entry, exists := kr.entries[id]
	if !exists {
		return errors.New("key not found")
	}
	entry.Verified = true
	kr.entries[id] = entry
	return kr.SaveUnlocked(kr.entries)
}
