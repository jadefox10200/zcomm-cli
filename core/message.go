package core

import (
	"encoding/json"
	"time"
)

type ZMessage struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Timestamp int64  `json:"timestamp"`
	Type      string `json:"type"` // e.g. text, html, file
	Body      string `json:"body"` // Base64 encoded
	Signature string `json:"signature"`
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
		Signature: EncodeKey(sig),
	}, nil
}

func (m *ZMessage) Validate(pubKey []byte) bool {
	raw := m.From + m.To + m.Type + m.Body + string(m.Timestamp)
	sig, err := DecodeKey(m.Signature)
	if err != nil {
		return false
	}
	return VerifySignature(pubKey, []byte(raw), sig)
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
