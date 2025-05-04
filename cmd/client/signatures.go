// cmd/client/signatures.go
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/jadefox10200/zcomm/core"
)

// func signNotification(notif core.Notification, edPriv ed25519.PrivateKey) (string, error) {
// 	if len(edPriv) != 64 {
// 		return "", fmt.Errorf("invalid private key length: got %d, want 64", len(edPriv))
// 	}
// 	hashInput := fmt.Sprintf("%s%s%s%s%d%s", notif.UUID, notif.DispatchID, notif.From, notif.To, notif.Timestamp, notif.Type)
// 	digest := sha256.Sum256([]byte(hashInput))
// 	sig := ed25519.Sign(edPriv, digest[:])
// 	return base64.StdEncoding.EncodeToString(sig), nil
// }

// func signNotification(notif core.Notification, edPriv ed25519.PrivateKey) (string, error) {
// 	if len(edPriv) != 64 {
// 		return "", fmt.Errorf("invalid private key length: got %d, want 64", len(edPriv))
// 	}
// 	hashInput := fmt.Sprintf("%s%s%s%s%d%s%s", notif.UUID, notif.DispatchID, notif.From, notif.To, notif.Timestamp, notif.Type, notif.PubKey)
// 	digest := sha256.Sum256([]byte(hashInput))
// 	sig := ed25519.Sign(edPriv, digest[:])
// 	return base64.StdEncoding.EncodeToString(sig), nil
// }

// func signNotification(notif core.Notification, edPriv ed25519.PrivateKey) (string, error) {
// 	data := []byte(fmt.Sprintf("%s%d", notif.UUID, notif.Timestamp))
// 	// privKey, err := base64.StdEncoding.DecodeString(edPriv)
// 	// if err != nil {
// 	// 	return "", fmt.Errorf("decode private key: %w", err)
// 	// }
// 	if len(edPriv) != ed25519.PrivateKeySize {
// 		return "", fmt.Errorf("invalid private key length: got %d, want %d", len(edPriv), ed25519.PrivateKeySize)
// 	}
// 	signature := ed25519.Sign(edPriv, data)
// 	return base64.StdEncoding.EncodeToString(signature), nil
// }

// func verifyNotification(notif core.Notification, publicKey []byte) bool {
// 	data := []byte(fmt.Sprintf("%s%d", notif.UUID, notif.Timestamp))
// 	signature, err := base64.StdEncoding.DecodeString(notif.Signature)
// 	if err != nil {
// 		return false
// 	}
// 	return ed25519.Verify(publicKey, data, signature)
// }

// verifyDispatch verifies the signature of a received dispatch.
func verifyDispatch(disp core.Dispatch, keys core.PublicKeys) (bool, error) {
	pubKey, err := base64.StdEncoding.DecodeString(keys.EdPub)
	if err != nil {
		return false, fmt.Errorf("decode public key: %w", err)
	}
	valid, err := core.VerifyDispatch(disp, pubKey)
	if err != nil || !valid {
		return false, fmt.Errorf("invalid signature from %s: %v", disp.From, err)
	}
	return true, nil
}

// createReqSignature generates a signature for a request.
func createReqSignature(zid string, edPriv ed25519.PrivateKey) (string, string, error) {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	sigData := []byte(zid + ts)
	sig, err := core.Sign(sigData, edPriv)
	if err != nil {
		return "", "", fmt.Errorf("sign message: %w", err)
	}
	return ts, sig, nil
}
