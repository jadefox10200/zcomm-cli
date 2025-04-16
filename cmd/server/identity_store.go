//cmd/server/identity_store.go
package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/jadefox10200/zcomm/core"
)

type Identity struct {
	ID          string `json:"id"`
	VerifyKey   string `json:"verify_key"`
	ExchangeKey string `json:"exchange_key"`
}

func (i Identity) ToPublicKeys() core.PublicKeys {
	return core.PublicKeys{
		ID:      i.ID,
		EdPub:   i.VerifyKey,
		ECDHPub: i.ExchangeKey,
	}
}

type IdentityStore struct {
	sync.RWMutex
	Identities map[string]Identity
	FilePath   string
}

func NewIdentityStore(path string) (*IdentityStore, error) {
	store := &IdentityStore{
		Identities: make(map[string]Identity),
		FilePath:   path,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &store.Identities); err != nil {
			return nil, err
		}
	} else if os.IsNotExist(err) {
		// Create empty identities.json
		if err := store.save(); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	return store, nil
}

func (s *IdentityStore) Add(identity Identity) error {
	s.Lock()
	defer s.Unlock()

	if _, exists := s.Identities[identity.ID]; exists {
		return errors.New("identity already exists")
	}
	s.Identities[identity.ID] = identity
	return s.save()
}

func (s *IdentityStore) save() error {
	data, err := json.MarshalIndent(s.Identities, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.FilePath), 0755); err != nil {
		return err
	}
	return os.WriteFile(s.FilePath, data, 0644)
}