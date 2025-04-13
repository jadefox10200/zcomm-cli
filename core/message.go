package core

import (
	"encoding/json"
	"encoding/base64"
	"errors"
	"time"
	"crypto/ed25519"
)

type ZMessage struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Timestamp int64  `json:"timestamp"`
	Type      string `json:"type"` // e.g. text, html, file
	Body      string `json:"body"` // Base64 encoded
	Signature string `json:"signature"`
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

func NewEncryptedMessage(from, to, msgType, body string, privKey ed25519.PrivateKey, aesKey []byte) (*ZMessage, error) {
	ts := time.Now().Unix()

	encryptedBody, err := EncryptAESGCM(aesKey, []byte(body))
	if err != nil {
		return nil, err
	}

	raw := from + to + msgType + encryptedBody + string(ts)
	sig := SignMessage(privKey, []byte(raw))

	return &ZMessage{
		From:      from,
		To:        to,
		Timestamp: ts,
		Type:      msgType,
		Body:      encryptedBody,
		Signature: sig,
	}, nil
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

func (m *ZMessage) DecryptBody(aesKey []byte) (string, error) {
	plaintext, err := DecryptAESGCM(aesKey, m.Body)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
