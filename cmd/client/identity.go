package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

type Identity struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	SecretKey string `json:"secret_key"`
}

// GenerateIdentity creates a new Curve25519 keypair and stores it locally
func GenerateIdentity(filepath string) (*Identity, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	id := base64.RawURLEncoding.EncodeToString(pub[:])
	identity := &Identity{
		ID:        id,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub[:]),
		SecretKey: base64.RawURLEncoding.EncodeToString(priv[:]),
	}

	// Store the identity
	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(filepath), 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath, data, 0600); err != nil {
		return nil, err
	}

	return identity, nil
}
