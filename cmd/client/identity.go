// cmd/client/identity.go
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jadefox10200/zcomm/core"
)

type Identity struct {
	ID                string `json:"id"`
	EdPub             string `json:"ed_pub"`
	EdPrivEncrypted   string `json:"ed_priv_encrypted"`
	ECDHPub           string `json:"ecdh_pub"`
	ECDHPrivEncrypted string `json:"ecdh_priv_encrypted"`
	EdPrivNonce       string `json:"ed_priv_nonce"`
	ECDHPrivNonce     string `json:"ecdh_priv_nonce"`
	Created           int64  `json:"created"`
}

func (id *Identity) ToKeyStore() (*KeyStore, error) {
	return &KeyStore{
		ID:      id.ID,
		EdPub:   id.EdPub,
		ECDHPub: id.ECDHPub,
	}, nil
}

type IdentityStore struct {
	mu       sync.RWMutex
	filepath string
	identity *Identity
}

func getIdentityPath(zid string) string {
	return filepath.Join("data", "identities", fmt.Sprintf("identity_%s.json", zid))
}

func LoadIdentity(path string) (*IdentityStore, error) {
	is := &IdentityStore{filepath: path}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return is, nil
		}
		return nil, fmt.Errorf("open identity file: %w", err)
	}
	defer file.Close()

	var ident Identity
	if err := json.NewDecoder(file).Decode(&ident); err != nil {
		return nil, fmt.Errorf("decode identity: %w", err)
	}
	is.identity = &ident
	return is, nil
}

func (is *IdentityStore) SaveUnlocked(identity *Identity) error {
	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}
	dir := filepath.Dir(is.filepath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create identity dir: %w", err)
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

func (is *IdentityStore) CreateIfNotExists(encryptionKey []byte) (*Identity, error) {
	is.mu.Lock()
	defer is.mu.Unlock()

	if is.identity != nil {
		return is.identity, nil
	}

	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("invalid encryption key size: got %d, expected 32", len(encryptionKey))
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 keys: %w", err)
	}
	if len(priv) != 64 {
		return nil, fmt.Errorf("invalid ed25519 private key length: got %d, expected 64", len(priv))
	}
	fmt.Printf("Generated Ed25519 private key length: %d\n", len(priv))

	ecdh, err := core.GenerateECDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ecdh keys: %w", err)
	}

	id := core.GenerateZID(pub)

	edPrivCipher, edPrivNonce, err := core.EncryptAESGCM(encryptionKey, priv)
	if err != nil {
		return nil, fmt.Errorf("encrypt ed private key: %w", err)
	}
	fmt.Printf("Encrypted Ed25519 private key ciphertext length: %d\n", len(edPrivCipher))
	if len(edPrivCipher) != 80 {
		return nil, fmt.Errorf("unexpected ed25519 ciphertext length: got %d, expected 80", len(edPrivCipher))
	}
	ecdhPrivCipher, ecdhPrivNonce, err := core.EncryptAESGCM(encryptionKey, ecdh.PrivateKey[:])
	if err != nil {
		return nil, fmt.Errorf("encrypt ecdh private key: %w", err)
	}
	fmt.Printf("Encrypted ECDH private key ciphertext length: %d\n", len(ecdhPrivCipher))
	if len(ecdhPrivCipher) != 48 {
		return nil, fmt.Errorf("unexpected ecdh ciphertext length: got %d, expected 48", len(ecdhPrivCipher))
	}
	identity := Identity{
		ID:                id,
		EdPub:             core.EncodeKey(pub),
		EdPrivEncrypted:   base64.StdEncoding.EncodeToString(edPrivCipher),
		ECDHPub:           core.EncodeKey(ecdh.PublicKey[:]),
		ECDHPrivEncrypted: base64.StdEncoding.EncodeToString(ecdhPrivCipher),
		EdPrivNonce:       base64.StdEncoding.EncodeToString(edPrivNonce),
		ECDHPrivNonce:     base64.StdEncoding.EncodeToString(ecdhPrivNonce),
		Created:           time.Now().Unix(),
	}

	is.identity = &identity
	if err := is.SaveUnlocked(&identity); err != nil {
		return nil, fmt.Errorf("save identity: %w", err)
	}
	return &identity, nil
}

func GenerateAndStoreNewIdentity(encryptionKey []byte) (*Identity, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("invalid encryption key size: got %d, expected 32", len(encryptionKey))
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 keys: %w", err)
	}
	if len(priv) != 64 {
		return nil, fmt.Errorf("invalid ed25519 private key length: got %d, expected 64", len(priv))
	}
	fmt.Printf("Generated Ed25519 private key length: %d\n", len(priv))

	ecdh, err := core.GenerateECDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ecdh keys: %w", err)
	}

	zid := core.GenerateZID(pub)

	edPrivCipher, edPrivNonce, err := core.EncryptAESGCM(encryptionKey, priv)
	if err != nil {
		return nil, fmt.Errorf("encrypt ed private key: %w", err)
	}
	fmt.Printf("Encrypted Ed25519 private key ciphertext length: %d\n", len(edPrivCipher))
	if len(edPrivCipher) != 80 {
		return nil, fmt.Errorf("unexpected ed25519 ciphertext length: got %d, expected 80", len(edPrivCipher))
	}
	ecdhPrivCipher, ecdhPrivNonce, err := core.EncryptAESGCM(encryptionKey, ecdh.PrivateKey[:])
	if err != nil {
		return nil, fmt.Errorf("encrypt ecdh private key: %w", err)
	}
	fmt.Printf("Encrypted ECDH private key ciphertext length: %d\n", len(ecdhPrivCipher))
	if len(ecdhPrivCipher) != 48 {
		return nil, fmt.Errorf("unexpected ecdh ciphertext length: got %d, expected 48", len(ecdhPrivCipher))
	}
	identity := Identity{
		ID:                zid,
		EdPub:             core.EncodeKey(pub),
		EdPrivEncrypted:   base64.StdEncoding.EncodeToString(edPrivCipher),
		ECDHPub:           core.EncodeKey(ecdh.PublicKey[:]),
		ECDHPrivEncrypted: base64.StdEncoding.EncodeToString(ecdhPrivCipher),
		EdPrivNonce:       base64.StdEncoding.EncodeToString(edPrivNonce),
		ECDHPrivNonce:     base64.StdEncoding.EncodeToString(ecdhPrivNonce),
		Created:           time.Now().Unix(),
	}

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

	resp, err := http.Post(fmt.Sprintf("%s/identity", serverURL), "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("register identity: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("register identity failed: %s", string(body))
	}

	path := getIdentityPath(zid)
	is := &IdentityStore{filepath: path}
	if err := is.SaveUnlocked(&identity); err != nil {
		return nil, fmt.Errorf("save identity: %w", err)
	}

	return &identity, nil
}

func DecryptIdentity(identity *Identity, encryptionKey []byte) (ed25519.PrivateKey, [32]byte, error) {
	if len(encryptionKey) != 32 {
		return nil, [32]byte{}, fmt.Errorf("invalid encryption key size: got %d, expected 32", len(encryptionKey))
	}

	edPrivCipher, err := base64.StdEncoding.DecodeString(identity.EdPrivEncrypted)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("decode ed priv: %w", err)
	}
	fmt.Printf("Ed25519 private key ciphertext length: %d\n", len(edPrivCipher))
	if len(edPrivCipher) != 80 {
		fmt.Printf("Warning: Expected Ed25519 ciphertext length 80, got %d. Consider regenerating identity.\n", len(edPrivCipher))
	}
	edPrivNonce, err := base64.StdEncoding.DecodeString(identity.EdPrivNonce)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("decode ed nonce: %w", err)
	}
	edPriv, err := core.DecryptAESGCM(encryptionKey, edPrivNonce, edPrivCipher)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("decrypt ed priv: %w", err)
	}
	fmt.Printf("Decrypted Ed25519 private key length: %d\n", len(edPriv))
	if len(edPriv) != 64 {
		if len(edPriv) == 80 {
			fmt.Printf("Warning: Decrypted Ed25519 private key is 80 bytes, trimming to 64 bytes. Please regenerate identity.\n")
			edPriv = edPriv[:64]
		} else {
			return nil, [32]byte{}, fmt.Errorf("invalid decrypted ed25519 private key length: got %d, expected 64", len(edPriv))
		}
	}

	ecdhPrivCipher, err := base64.StdEncoding.DecodeString(identity.ECDHPrivEncrypted)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("decode ecdh priv: %w", err)
	}
	fmt.Printf("ECDH private key ciphertext length: %d\n", len(ecdhPrivCipher))
	if len(ecdhPrivCipher) != 48 {
		fmt.Printf("Warning: Expected ECDH ciphertext length 48, got %d. Consider regenerating identity.\n", len(ecdhPrivCipher))
	}
	ecdhPrivNonce, err := base64.StdEncoding.DecodeString(identity.ECDHPrivNonce)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("decode ecdh nonce: %w", err)
	}
	ecdhPrivBytes, err := core.DecryptAESGCM(encryptionKey, ecdhPrivNonce, ecdhPrivCipher)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("decrypt ecdh priv: %w", err)
	}
	fmt.Printf("Decrypted ECDH private key length: %d\n", len(ecdhPrivBytes))
	if len(ecdhPrivBytes) != 32 {
		return nil, [32]byte{}, fmt.Errorf("invalid decrypted ecdh private key length: got %d, expected 32", len(ecdhPrivBytes))
	}
	var ecdhPriv [32]byte
	copy(ecdhPriv[:], ecdhPrivBytes)

	return ed25519.PrivateKey(edPriv), ecdhPriv, nil
}
