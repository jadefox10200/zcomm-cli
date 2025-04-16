package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type PublicKeys struct {
	ID      string `json:"id"`
	EdPub   string `json:"ed_pub"`
	ECDHPub string `json:"ecdh_pub"`
}

type Dispatch struct {
	From            string   `json:"from"`            // Sender zID
	To              []string `json:"to"`              // Recipient zIDs
	CC              []string `json:"cc"`              // CC zIDs
	Via             []string `json:"via"`             // Intermediary zIDs
	Subject         string   `json:"subject"`         // Dispatch subject
	Body            string   `json:"body"`            // Encrypted body
	Attachments     []string `json:"attachments"`     // Encrypted file IDs (future)
	Timestamp       int64    `json:"timestamp"`
	ConversationID  string   `json:"conversation_id"` // UUID for conversation
	Status          string   `json:"status"`          // "open", "closed"
	Signature       string   `json:"signature"`
	EphemeralPubKey string   `json:"ephemeral_pub_key"`
	Nonce           string   `json:"nonce"`
	Basket          string   `json:"basket"` // IN, OUT, PENDING, ARCHIVED
}

func NewEncryptedDispatch(from string, to, cc, via []string, subject, body string, attachments []string, privKey ed25519.PrivateKey, sharedKey [32]byte, ephemeralPub []byte, convID string) (*Dispatch, error) {
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
		From:            from,
		To:              to,
		CC:              cc,
		Via:             via,
		Subject:         subject,
		Body:            base64.StdEncoding.EncodeToString(encrypted),
		Attachments:     attachments,
		Timestamp:       timestamp,
		ConversationID:  convID,
		Status:          "open",
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		EphemeralPubKey: base64.StdEncoding.EncodeToString(ephemeralPub),
		Basket:          "OUT",
	}

	hashInput := fmt.Sprintf("%s%s%s%s%s%d%s%s", disp.From, strings.Join(append(disp.To, disp.CC...), ","), disp.Subject, disp.Body, disp.Nonce, disp.Timestamp, disp.ConversationID, disp.EphemeralPubKey)
	digest := sha256.Sum256([]byte(hashInput))
	sig, err := Sign(digest[:], privKey)
	if err != nil {
		return nil, fmt.Errorf("sign dispatch: %w", err)
	}
	disp.Signature = sig

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

func Sign(data []byte, privKey ed25519.PrivateKey) (string, error) {
	sig := ed25519.Sign(privKey, data)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func VerifySignature(pubKey, data []byte, signature string) (bool, error) {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	return ed25519.Verify(pubKey, data, sig), nil
}