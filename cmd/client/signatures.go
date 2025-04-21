//cmd/client/signatures.go
package main 

import (
	"fmt"
	"time"
	"encoding/base64"
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/jadefox10200/zcomm/core"
)

func signNotification(identity *Identity, notif core.Notification) (string, error) {
    data := []byte(fmt.Sprintf("%s%d", notif.UUID, notif.Timestamp))
    privKey, err := base64.StdEncoding.DecodeString(identity.EdPriv)
    if err != nil {
        return "", fmt.Errorf("decode private key: %w", err)
    }
    if len(privKey) != ed25519.PrivateKeySize {
        return "", fmt.Errorf("invalid private key length: got %d, want %d", len(privKey), ed25519.PrivateKeySize)
    }
    signature := ed25519.Sign(ed25519.PrivateKey(privKey), data)
    return base64.StdEncoding.EncodeToString(signature), nil
}

func verifyNotification(notif core.Notification, publicKey []byte) bool {
    data := []byte(fmt.Sprintf("%s%d", notif.UUID, notif.Timestamp))
    signature, err := base64.StdEncoding.DecodeString(notif.Signature)
    if err != nil {
        return false
    }
    return ed25519.Verify(publicKey, data, signature)
}

// verifyDispatch verifies the signature of a received dispatch.
func verifyDispatch(disp core.Dispatch, keys core.PublicKeys) (bool, error) {
	pubKey, err := base64.StdEncoding.DecodeString(keys.EdPub)
	if err != nil {
		return false, fmt.Errorf("decode public key: %w", err)
	}

	hashInput := core.GenerateDispatchHash(disp)
	// hashInput := fmt.Sprintf("%s%s%s%s%s%d%s%s", disp.From, strings.Join(disp.To, ","), disp.Subject, disp.Body, disp.Nonce, disp.Timestamp, disp.ConversationID, disp.EphemeralPubKey)
	digest := sha256.Sum256([]byte(hashInput))
	valid, err := core.VerifySignature(pubKey, digest[:], disp.Signature)
	if err != nil || !valid {
		return false, fmt.Errorf("invalid signature from %s: %v", disp.From, err)
	}
	return true, nil
}


//createReqSignature generates a signature for a request.
func createReqSignature(zid string, edPriv ed25519.PrivateKey) (string, string, error) {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	sigData := []byte(zid + ts)
	sig, err := core.Sign(sigData, edPriv)
	if err != nil {
		return "", "", fmt.Errorf("sign message: %w", err)
	}
	return ts, sig, nil
}

// //don't use
// func SignRequest() {
// 	//sign the request
// 	sigData := []byte(fmt.Sprintf("%s%d%s", zid, disp.Timestamp))
// 	sig, err := core.Sign(sigData, edPriv)
// 	if err != nil {
// 		return fmt.Errorf("sign confirm: %w", err)
// 	}
// }