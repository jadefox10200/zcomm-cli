package core

import (
	"encoding/json"
	"encoding/base64"
	"errors"
	"time"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
)

type ZMessage struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Timestamp int64  `json:"timestamp"`
	Type      string `json:"type"` // e.g. text, html, file
	Body      string `json:"body"` // Base64 encoded
	Signature string `json:"signature"`

	// New fields for chaining
	PrevHash  string `json:"prev_hash"`  // base64-encoded previous hash
	Hash      string `json:"hash"`       // base64-encoded hash of this message
	Nonce string `json:"nonce"`
}

//EncodeKey 
func EncodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func DecodeKey(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

//VerifySignature(pubKey, []byte(raw), sig)
func VerifySignature(pubKey ed25519.PublicKey, messageBody []byte, signatureB64 string) (bool, error) {
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, err
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return false, errors.New("invalid public key length")
	}
	return ed25519.Verify(pubKey, messageBody, sig), nil
}

func NewEncryptedMessage(from, to, msgType, plaintext string, privKey ed25519.PrivateKey, sharedKey []byte, prevHash string) (*ZMessage, error) {
    // Encrypt message
    ciphertext, nonce, err := EncryptMessage([]byte(plaintext), sharedKey)
    if err != nil {
        return nil, err
    }

    ts := time.Now().Unix()

    // Base64 encode
    bodyB64 := base64.StdEncoding.EncodeToString(ciphertext)
    nonceB64 := base64.StdEncoding.EncodeToString(nonce)

    // Compose base message
    msg := &ZMessage{
        From:      from,
        To:        to,
        Type:      msgType,
        Body:      bodyB64,
        Nonce:     nonceB64,
        Timestamp: ts,
        PrevHash:  prevHash,
    }

    // Hash the message content
    hashInput := fmt.Sprintf("%s%s%s%s%s%d%s", from, to, msgType, bodyB64, nonceB64, ts, prevHash)
    digest := sha256.Sum256([]byte(hashInput))
    msg.Hash = base64.StdEncoding.EncodeToString(digest[:])

    // Sign the hash
    sig := ed25519.Sign(privKey, digest[:])
    msg.Signature = base64.StdEncoding.EncodeToString(sig)

    return msg, nil
}


func (m *ZMessage) Validate(pubKey []byte) bool {
	raw := m.From + m.To + m.Type + m.Body + string(m.Timestamp)
	sig, err := DecodeKey(m.Signature)
	if err != nil {
		return false
	}
	valid, err := VerifySignature(pubKey, []byte(raw), EncodeKey(sig))
	if err != nil {
		return false
	}
	return valid
}

func (m *ZMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

func (zm *ZMessage) DecryptBody(sharedKey []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(zm.Body)
	if err != nil {
		return "", err
	}

	nonce, err := base64.StdEncoding.DecodeString(zm.Nonce)
	if err != nil {
		return "", err
	}

	plaintext, err := DecryptAESGCM(sharedKey, nonce, ciphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

