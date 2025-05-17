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
	UUID            string `json:"uuid" db:"uuid"`
	From            string `json:"from_zid" db:"from_zid"`
	To              string `json:"to_zid" db:"to_zid"`
	CC              []string
	Subject         string `json:"subject" db:"subject"`
	Body            string `json:"body" db:"body"`
	LocalNonce      string `json:"local_nonce" db:"local_nonce"`
	Nonce           string `json:"nonce" db:"nonce"`
	Timestamp       int64  `json:"timestamp" db:"timestamp"`
	ConversationID  string `json:"conversation_id" db:"conversation_id"`
	Signature       string `json:"signature" db:"signature"`
	EphemeralPubKey string `json:"ephemeral_pub_key" db:"ephemeral_pub_key"`
	IsEnd           bool   `json:"is_end" db:"is_end"`
}

type BasketDispatch struct {
	DispatchID string `json:"dispatch_id" db:"dispatch_id"`
	To         string `json:"to_zid" db:"to_zid"`
	From       string `json:"from_zid" db:"from_zid"`
	Subject    string `json:"subject" db:"subject"`
	Timestamp  int64  `json:"timestamp" db:"timestamp"`
	IsEnd      bool   `json:"is_end" db:"is_end"`
	Status     string `json:"status" db:"status"`
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

func NewEncryptedDispatch(from string, to string, cc, via []string, subject, body string, convID string, privKey ed25519.PrivateKey, sharedKey [32]byte, ephemeralPub []byte, isEnd bool) (*Dispatch, error) {
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

	if to == "" {
		return nil, fmt.Errorf("you sent the dispatch to no one")
	} else {
		fmt.Printf("Sending to: %s\n", to)
	}

	//if the convID is empty, this must be a NEW dispatch so we need to start the conversation:
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
