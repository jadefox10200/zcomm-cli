//cmd/client/keyring.go
package main

import (
	"encoding/json"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
	"time"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

type PublicKeyEntry struct {
	ID       string `json:"id"`
	EdPub    string `json:"ed_pub"`
	ECDHPub  string `json:"ecdh_pub"`
	Verified bool   `json:"verified"`
	AddedAt  int64  `json:"added_at"`
	Alias    string `json:"alias"`
}

type KeyRing struct {
	mu       sync.RWMutex
	filepath string
	Keys     []PublicKeyEntry `json:"keys"`
}

func LoadKeyRing(path string) (*KeyRing, error) {
	kr := &KeyRing{filepath: path}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return kr, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keyring: %w", err)
	}

	if err := json.Unmarshal(data, &kr); err != nil {
		return nil, fmt.Errorf("unmarshal keyring: %w", err)
	}
	return kr, nil
}

func SaveKeyRing(path string, kr *KeyRing) error {
	data, err := json.MarshalIndent(kr, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal keyring: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create keyring dir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

func (kr *KeyRing) AddKey(entry PublicKeyEntry) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	for i, k := range kr.Keys {
		if k.ID == entry.ID {
			kr.Keys[i] = entry
			return nil
		}
	}
	entry.AddedAt = time.Now().Unix()
	kr.Keys = append(kr.Keys, entry)
	return SaveKeyRing(kr.filepath, kr)
}

type KeyStore struct {
	ID       string `json:"id"`
	EdPub    string `json:"ed_pub"`
	EdPriv   string `json:"ed_priv"`
	ECDHPub  string `json:"ecdh_pub"`
	ECDHPriv string `json:"ecdh_priv"`
}

func LoadOrCreateKeyPair(zid string) (*KeyStore, error) {
	path := filepath.Join(zid, "keys.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(zid, 0700); err != nil {
			return nil, fmt.Errorf("create directory: %w", err)
		}

		edPub, edPriv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("generate ed25519 key: %w", err)
		}

		ecdhPrivBytes := make([]byte, 32)
		if _, err := rand.Read(ecdhPrivBytes); err != nil {
			return nil, fmt.Errorf("generate ecdh private key: %w", err)
		}

		ecdhPub, err := curve25519.X25519(ecdhPrivBytes, curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("generate ecdh public key: %w", err)
		}

		ks := &KeyStore{
			ID:       zid,
			EdPub:    base64.StdEncoding.EncodeToString(edPub),
			EdPriv:   base64.StdEncoding.EncodeToString(edPriv),
			ECDHPub:  base64.StdEncoding.EncodeToString(ecdhPub),
			ECDHPriv: base64.StdEncoding.EncodeToString(ecdhPrivBytes),
		}

		data, err := json.MarshalIndent(ks, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal keys: %w", err)
		}

		if err := os.WriteFile(path, data, 0600); err != nil {
			return nil, fmt.Errorf("write keys: %w", err)
		}

		return ks, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keys: %w", err)
	}

	var ks KeyStore
	if err := json.Unmarshal(data, &ks); err != nil {
		return nil, fmt.Errorf("unmarshal keys: %w", err)
	}
	return &ks, nil
}