package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type PublicKeys struct {
	ID      string `json:"id"`
	EdPub   string `json:"ed_pub"`
	ECDHPub string `json:"ecdh_pub"`
}

type Dispatch struct {
	UUID            string
	From            string
	To              []string
	CC              []string
	Subject         string
	Body            string
	LocalNonce      string
	Nonce           string
	Timestamp       int64
	ConversationID  string
	Signature       string
	EphemeralPubKey string
	IsEnd           bool
}

type Notification struct {
	UUID       string `json:"uuid"`
	DispatchID string `json:"dispatchID"`
	From       string `json:"from"`
	To         string `json:"to"`
	Type       string `json:"type"`
	Timestamp  int64  `json:"timestamp"`
	Signature  string `json:"signature"`
}

type ReceiveRequest struct {
	ID  string `json:"id"`
	TS  string `json:"ts"`
	Sig string `json:"sig"`
}

func NewEncryptedDispatch(from string, to, cc, via []string, subject, body string, convID string, privKey ed25519.PrivateKey, sharedKey [32]byte, ephemeralPub []byte, isEnd bool) (*Dispatch, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	cipherBlock, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	encrypted := gcm.Seal(nil, nonce, []byte(body), nil)
	timestamp := time.Now().Unix()
	if convID == "" {
		convID = uuid.New().String()
	}

	disp := &Dispatch{
		UUID:            uuid.New().String(),
		From:            from,
		To:              to,
		CC:              cc,
		Subject:         subject,
		Body:            base64.StdEncoding.EncodeToString(encrypted),
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		Timestamp:       timestamp,
		ConversationID:  convID,
		EphemeralPubKey: base64.StdEncoding.EncodeToString(ephemeralPub),
		IsEnd:           isEnd,
	}

	err = SignDispatch(disp, privKey)
	if err != nil {
		return nil, fmt.Errorf("sign dispatch: %w", err)
	}

	return disp, nil
}

func (d *Dispatch) DecryptBody(sharedKey [32]byte) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(d.Body)
	if err != nil {
		return "", fmt.Errorf("decode body: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(d.Nonce)
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}

	cipherBlock, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt body: %w", err)
	}

	return string(plaintext), nil
}
