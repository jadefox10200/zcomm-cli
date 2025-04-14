package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"io"
	"fmt"
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
		ecdhPrivRaw, err := base64.StdEncoding.DecodeString(ks.ECDHPriv)
		if err != nil {
			return nil, nil, [32]byte{}, err
		}
		var ecdhPriv [32]byte 
		copy(ecdhPriv[:], ecdhPrivRaw)
		return &ks, edPriv, ecdhPriv, nil
	}

	fmt.Println("about to create new keys")
	//create new keys
	edPub, edPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	var ecdhPriv [32]byte 
	if _, err := io.ReadFull(os.Stdin, ecdhPriv[:]); err != nil {
		return nil, nil, [32]byte{}, err
	}
	ecdhPub, err := curve25519.X25519(ecdhPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}

	fmt.Println("made the keys")
	ks := &KeyStore{
		ID: id,
		EdPriv: base64.StdEncoding.EncodeToString(edPriv),
		EdPub: base64.StdEncoding.EncodeToString(edPub),
		ECDHPriv:  base64.StdEncoding.EncodeToString(ecdhPriv[:]),
		ECDHPub: base64.StdEncoding.EncodeToString(ecdhPub),
	}
	err = SaveKeyPair(id, ks)
	return ks, edPriv, ecdhPriv, err 
}

