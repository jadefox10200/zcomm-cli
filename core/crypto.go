//core/crypto.go
package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/base32"

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

func DeriveSharedSecret(priv, pub [32]byte) ([32]byte, error) {
	shared, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return [32]byte{}, err
	}
	var result [32]byte
	copy(result[:], shared)
	return result, nil
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

func SignMessageBody(privateKey ed25519.PrivateKey, messageBody []byte) string {
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

func GenerateZID(pub ed25519.PublicKey) string {
	hash := sha256.Sum256(pub)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])
	numeric := ""
	for _, r := range encoded {
		if len(numeric) == 9 {
			break
		}
		if r >= '2' && r <= '7' {
			numeric += string(r)
		}
	}
	for len(numeric) < 9 {
		numeric += "0"
	}
	return "z" + numeric
}

func EncodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}