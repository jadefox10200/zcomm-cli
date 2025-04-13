package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

type ECDHKeyPair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
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
	hash := sha256.Sum256(secret) // derive AES key
	return hash[:], nil
}

func EncryptAESGCM(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptAESGCM(key []byte, encrypted string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}
