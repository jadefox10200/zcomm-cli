package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/jadefox10200/zcomm/core"
)

type KeyStore struct {
	sync.RWMutex
	Keys     map[string]core.PublicKeys
	FilePath string
}

func NewKeyStore(path string) (*KeyStore, error) {
	store := &KeyStore{
		Keys:     make(map[string]core.PublicKeys),
		FilePath: path,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err == nil {
		json.Unmarshal(data, &store.Keys)
	}
	return store, nil
}

func (s *KeyStore) Set(id string, keys core.PublicKeys) {
	s.Lock()
	defer s.Unlock()
	s.Keys[id] = keys
}

func (s *KeyStore) Get(id string) (core.PublicKeys, bool) {
	s.RLock()
	defer s.RUnlock()
	k, ok := s.Keys[id]
	return k, ok
}

func (s *KeyStore) Save() error {
	s.RLock()
	defer s.RUnlock()
	data, err := json.MarshalIndent(s.Keys, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.FilePath, data, 0644)
}
