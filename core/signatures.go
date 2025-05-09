package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// Sign generates a base64-encoded signature for the given data.
func Sign(data []byte, privKey ed25519.PrivateKey) (string, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key length: got %d, want %d", len(privKey), ed25519.PrivateKeySize)
	}
	sig := ed25519.Sign(privKey, data)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifySignature verifies a base64-encoded signature against the provided data and public key.
func VerifySignature(pubKey, data []byte, signature string) (bool, error) {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	return ed25519.Verify(pubKey, data, sig), nil
}

// GenerateDispatchHash creates a consistent hash input for a Dispatch.
func GenerateDispatchHash(disp Dispatch) string {
	hashInput := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s|%s|%t",
		disp.From,
		strings.Join(disp.To, ","),
		strings.Join(disp.CC, ","),
		disp.Subject,
		disp.Body,
		disp.Timestamp,
		disp.ConversationID,
		disp.EphemeralPubKey,
		disp.IsEnd)
	return hashInput
}

// GenerateNotificationHash creates a consistent hash input for a Notification.
func GenerateNotificationHash(notif Notification) string {
	hashInput := fmt.Sprintf("%s|%s|%s|%s|%s|%d",
		notif.UUID,
		notif.DispatchID,
		notif.From,
		notif.To,
		notif.Type,
		notif.Timestamp)
	// fmt.Printf("Notification hash input: %s\n", hashInput)
	return hashInput
}

// GenerateNotificationHash creates a consistent hash input for a Notification.
// func GenerateNotificationHash(notif Notification) string {
// 	hashInput := fmt.Sprintf("%s|%d", notif.UUID, notif.Timestamp)
// 	fmt.Printf("Notification hash input: %s\n", hashInput)
// 	return hashInput
// }

// SignDispatch signs a Dispatch using the provided private key.
func SignDispatch(disp *Dispatch, privKey ed25519.PrivateKey) error {
	hashInput := GenerateDispatchHash(*disp)
	digest := sha256.Sum256([]byte(hashInput))
	sig, err := Sign(digest[:], privKey)
	if err != nil {
		return fmt.Errorf("sign dispatch: %w", err)
	}
	disp.Signature = sig
	return nil
}

// SignNotification signs a Notification using the provided private key.
func SignNotification(notif *Notification, privKey ed25519.PrivateKey) error {
	hashInput := GenerateNotificationHash(*notif)
	digest := sha256.Sum256([]byte(hashInput))
	// fmt.Printf("Notification digest: %x\n", digest)
	sig, err := Sign(digest[:], privKey)
	if err != nil {
		return fmt.Errorf("sign notification: %w", err)
	}
	// fmt.Printf("Notification signature: %s\n", sig)
	notif.Signature = sig
	return nil
}

// VerifyDispatch verifies the signature of a Dispatch.
func VerifyDispatch(disp Dispatch, pubKey []byte) (bool, error) {
	hashInput := GenerateDispatchHash(disp)
	digest := sha256.Sum256([]byte(hashInput))
	return VerifySignature(pubKey, digest[:], disp.Signature)
}

// VerifyNotification verifies the signature of a Notification.
func VerifyNotification(notif Notification, pubKey []byte) (bool, error) {
	hashInput := GenerateNotificationHash(notif)
	digest := sha256.Sum256([]byte(hashInput))
	// fmt.Printf("Verify notification digest: %x\n", digest)
	return VerifySignature(pubKey, digest[:], notif.Signature)
}
