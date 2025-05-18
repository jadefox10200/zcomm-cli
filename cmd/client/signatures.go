// cmd/client/signatures.go
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/jadefox10200/zcomm/core"
)

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
