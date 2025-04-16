//cmd/server/keys.go
package main

import (
	"encoding/json"
	"net/http"
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

func HandlePublishKeys(store *KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var keys core.PublicKeys
		if err := json.NewDecoder(r.Body).Decode(&keys); err != nil {
			http.Error(w, "invalid key data", http.StatusBadRequest)
			return
		}
		store.Set(keys.ID, keys)
		if err := store.Save(); err != nil {
			http.Error(w, "failed to save keys", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleFetchKeys(store *KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		keys, ok := store.Get(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(keys)
	}
}