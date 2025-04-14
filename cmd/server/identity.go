package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
)

type Identity struct {
	ID         string `json:"id"`
	VerifyKey  string `json:"verify_key"`  // Base64
	ExchangeKey string `json:"exchange_key"` // Base64
}

type IdentityStore struct {
	sync.RWMutex
	Identities map[string]Identity
	FilePath   string
}

func NewIdentityStore(path string) (*IdentityStore, error) {
	absPath := filepath.Join("data", path)
	store := &IdentityStore{
		Identities: make(map[string]Identity),
		FilePath:   absPath,
	}

	// Ensure data directory exists
	err := os.MkdirAll(filepath.Dir(absPath), 0755)
	if err != nil {
		return nil, err
	}

	// Load from disk if exists
	data, err := ioutil.ReadFile(absPath)
	if err == nil {
		json.Unmarshal(data, &store.Identities)
	}

	return store, nil
}

func (s *IdentityStore) Save() error {
	s.RLock()
	defer s.RUnlock()

	data, err := json.MarshalIndent(s.Identities, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(s.FilePath, data, 0644)
}

func (s *IdentityStore) Add(identity Identity) error {
	s.Lock()
	defer s.Unlock()

	if _, exists := s.Identities[identity.ID]; exists {
		return errors.New("identity already exists")
	}

	s.Identities[identity.ID] = identity
	return s.Save()
}
