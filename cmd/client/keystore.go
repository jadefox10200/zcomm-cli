package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

type KeyStore struct {
	ID         string `json:"id"`
	EdPriv     string `json:"ed_priv"`
	EdPub      string `json:"ed_pub"`
	ECDHPriv   string `json:"ecdh_priv"`
	ECDHPub    string `json:"ecdh_pub"`
}

// Path where keys will be saved per user
func getKeyFilePath(id string) (string, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, ".zcomm", "keys", id+".json")
	return path, nil
}

// SaveKeyPair persists the keys to ~/.zcomm/keys/{id}.json
func SaveKeyPair(id string, keys *KeyStore) error {
	path, err := getKeyFilePath(id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadKeyPair attempts to load keys, or generates them if missing
func LoadOrCreateKeyPair(id string) (*KeyStore, ed25519.PrivateKey, [32]byte, error) {
	path, err := getKeyFilePath(id)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}

	if _, err := os.Stat(path); err == nil {
		// Load existing keys
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, [32]byte{}, err
		}
		var ks KeyStore
		if err := json.Unmarshal(data, &ks); err != nil {
			return nil, nil, [32]byte{}, err
		}
		edPriv, err := base64.StdEncoding.DecodeString(ks.EdPriv)
		if err != nil {
			return nil, nil, [32]byte{}, err
		}
		ecdhPrivRaw, err := base64.StdEncoding
