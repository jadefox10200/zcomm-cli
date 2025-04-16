//cmd/client/identity.go
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"bufio"
	"io"

	"github.com/jadefox10200/zcomm/core"
)

type Identity struct {
	ID       string `json:"id"`
	EdPub    string `json:"ed_pub"`
	EdPriv   string `json:"ed_priv"`
	ECDHPub  string `json:"ecdh_pub"`
	ECDHPriv string `json:"ecdh_priv"`
	Created  int64  `json:"created"`
}

func (id *Identity) ToKeyStore() (*KeyStore, error) {
	return &KeyStore{
		ID:       id.ID,
		EdPub:    id.EdPub,
		EdPriv:   id.EdPriv,
		ECDHPub:  id.ECDHPub,
		ECDHPriv: id.ECDHPriv,
	}, nil
}

type IdentityStore struct {
	mu       sync.RWMutex
	filepath string
	identity *Identity
}

func promptNewOrLogin() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("No --zid provided. Do you want to (L)og in or (C)reate new? ")
		choice, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Failed to read you data with error: %s\n", err.Error())
		}
		fmt.Println("got a string")
		choice = strings.TrimSpace(strings.ToLower(choice))

		if choice == "c" || choice == "create" {
			fmt.Println("correct logic")
			identity, err := GenerateAndStoreNewIdentity()
			if err != nil {
				return "", err
			}
			fmt.Printf("Created new Zcomm ID: %s\n", identity.ID)
			return identity.ID, nil
		} else if choice == "l" || choice == "login" {
			fmt.Print("Enter your existing Zcomm ID (z123456789): ")
			zidInput, _ := reader.ReadString('\n')
			zidInput = strings.TrimSpace(zidInput)
			if _, err := LoadIdentity(getIdentityPath(zidInput)); err != nil {
				return "", fmt.Errorf("identity for %s not found", zidInput)
			}
			return zidInput, nil
		}
		fmt.Println("Invalid choice. Please type 'L' or 'C'.")
	}
}

func getIdentityPath(zid string) string {
	return filepath.Join("data", "identities", fmt.Sprintf("identity_%s.json", zid))
}

func LoadIdentity(path string) (*IdentityStore, error) {
	is := &IdentityStore{filepath: path}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return is, nil // new store
		}
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var ident Identity
	if err := decoder.Decode(&ident); err != nil {
		return nil, err
	}
	is.identity = &ident
	return is, nil
}

func (is *IdentityStore) SaveUnlocked(identity *Identity) error {
	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(is.filepath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	return os.WriteFile(is.filepath, data, 0600)
}

func (is *IdentityStore) Save() error {
	is.mu.RLock()
	defer is.mu.RUnlock()

	if is.identity == nil {
		return errors.New("no identity to save")
	}
	return is.SaveUnlocked(is.identity)
}

func (is *IdentityStore) CreateIfNotExists() (*Identity, error) {
	is.mu.Lock()
	defer is.mu.Unlock()

	if is.identity != nil {
		return is.identity, nil
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	ecdh, err := core.GenerateECDHKeyPair()
	if err != nil {
		return nil, err
	}

	id := core.GenerateZID(pub)

	identity := &Identity{
		ID:       id,
		EdPub:    core.EncodeKey(pub),
		EdPriv:   core.EncodeKey(priv),
		ECDHPub:  core.EncodeKey(ecdh.PublicKey[:]),
		ECDHPriv: core.EncodeKey(ecdh.PrivateKey[:]),
		Created:  time.Now().Unix(),
	}

	is.identity = identity
	err = is.SaveUnlocked(identity)
	return identity, err
}

func GenerateAndStoreNewIdentity() (*Identity, error) {
	fmt.Println("make pub and priv")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	fmt.Println("made pub and priv")
	ecdh, err := core.GenerateECDHKeyPair()
	if err != nil {
		return nil, err
	}

	fmt.Println("made ecdh")
	zid := core.GenerateZID(pub)
	fmt.Println("made zid")

	identity := &Identity{
		ID:       zid,
		EdPub:    core.EncodeKey(pub),
		EdPriv:   core.EncodeKey(priv),
		ECDHPub:  core.EncodeKey(ecdh.PublicKey[:]),
		ECDHPriv: core.EncodeKey(ecdh.PrivateKey[:]),
		Created:  time.Now().Unix(),
	}

	// Register with server
	type serverIdentity struct {
		ID          string `json:"id"`
		VerifyKey   string `json:"verify_key"`
		ExchangeKey string `json:"exchange_key"`
	}
	sIdent := serverIdentity{
		ID:          zid,
		VerifyKey:   identity.EdPub,
		ExchangeKey: identity.ECDHPub,
	}
	data, err := json.Marshal(sIdent)
	if err != nil {
		return nil, fmt.Errorf("marshal identity: %w", err)
	}

	fmt.Println("about to post")
	resp, err := http.Post("http://localhost:8080/identity", "application/json", bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to register identity with server: %v\n", err)
		return nil, fmt.Errorf("register identity: %w", err)
	}
	fmt.Println("posted...")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Server rejected identity registration: %s\n", string(body))
		return nil, fmt.Errorf("register identity failed: %s", string(body))
	}

	path := getIdentityPath(zid)
	is := &IdentityStore{filepath: path}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create identity dir: %w", err)
	}
	if err := is.SaveUnlocked(identity); err != nil {
		return nil, err
	}

	return identity, nil
}