package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/curve25519"
)

type ECDHKeyPair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

type PublicKeys struct {
	ID       string `json:"id"`
	EdPub    string `json:"ed_pub"`
	ECDHPub  string `json:"ecdh_pub"`
}

type Message struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Type      string `json:"type"`      // e.g., "text"
	Body      string `json:"body"`      // encrypted (base64)
	Signature string `json:"signature"` // base64-encoded signature
}

// -----------------
// ECDH + AES-GCM
// -----------------

func EncryptMessage(plaintext []byte, key []byte) (ciphertext []byte, nonce []byte, err error) {
	return EncryptAESGCM(key, plaintext)
}

func EncryptWithNonce(key []byte, plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func GenerateECDHKeyPair() (*ECDHKeyPair, error) {
	var priv [32]byte
	_, err := rand.Read(priv[:])
	if err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var pubKey [32]byte
	copy(pubKey[:], pub)
	return &ECDHKeyPair{PublicKey: pubKey, PrivateKey: priv}, nil
}

func DeriveSharedSecret(privKey, pubKey [32]byte) ([]byte, error) {
	secret, err := curve25519.X25519(privKey[:], pubKey[:])
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(secret) // derive 32-byte AES key
	return hash[:], nil
}

func EncryptAESGCM(key []byte, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func DecryptAESGCM(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}


// -----------------
// Signing
// -----------------

func SignMessage(privateKey ed25519.PrivateKey, messageBody []byte) string {
	sig := ed25519.Sign(privateKey, messageBody)
	return base64.StdEncoding.EncodeToString(sig)
}

func VerifyMessageSignature(messageBody []byte, signatureB64 string, pubKey ed25519.PublicKey) bool {
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(pubKey, messageBody, sig)
}

func DecryptMessage(msg *ZMessage, sharedKey []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(msg.Body)
	if err != nil {
		return "", err
	}

	nonce, err := base64.StdEncoding.DecodeString(msg.Nonce)
	if err != nil {
		return "", err
	}

	plaintext, err := DecryptAESGCM(sharedKey, nonce, ciphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}



