// cmd/server/helperfuncs
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/jadefox10200/zcomm/core"
)

// / verifyNotification validates a notification's fields and signature.
func verifyNotification(req core.Notification, keys core.PublicKeys) error {
	// Validate all fields
	if req.UUID == "" {
		log.Printf("Missing UUID in notification")
		return fmt.Errorf("missing UUID")
	}
	if req.DispatchID == "" {
		log.Printf("Missing DispatchID in notification %s", req.UUID)
		return fmt.Errorf("missing DispatchID")
	}
	if req.From == "" {
		log.Printf("Missing From in notification %s", req.UUID)
		return fmt.Errorf("missing From")
	}
	if req.To == "" {
		log.Printf("Missing To in notification %s", req.UUID)
		return fmt.Errorf("missing To")
	}
	if req.Type != "delivery" && req.Type != "read" {
		log.Printf("Invalid Type in notification %s: %s", req.UUID, req.Type)
		return fmt.Errorf("invalid Type")
	}
	if req.Timestamp <= 0 {
		log.Printf("Invalid Timestamp in notification %s: %d", req.UUID, req.Timestamp)
		return fmt.Errorf("invalid Timestamp")
	}
	if req.Signature == "" {
		log.Printf("Missing Signature in notification %s", req.UUID)
		return fmt.Errorf("missing Signature")
	}

	// Validate public key
	pubKeyStored, err := base64.StdEncoding.DecodeString(keys.EdPub)
	if err != nil || len(pubKeyStored) != ed25519.PublicKeySize {
		log.Printf("Invalid stored public key for %s: %v, length=%d", req.From, err, len(pubKeyStored))
		return fmt.Errorf("invalid stored public key")
	}

	// Log notification for debugging
	notifJSON, _ := json.MarshalIndent(req, "", "  ")
	log.Printf("Verifying notification: %s\n", notifJSON)

	// Verify signature
	valid, err := core.VerifyNotification(req, pubKeyStored)
	if err != nil || !valid {
		log.Printf("Invalid signature for notification %s: err=%v, valid=%v", req.UUID, err, valid)
		return fmt.Errorf("invalid signature")
	}

	// TODO: Add additional validation
	// - Check if From and To are registered ZIDs
	// - Verify DispatchID exists and is associated with From or To
	// - Ensure Timestamp is within acceptable range (e.g., ±5 minutes)

	return nil
}

func (in *Inbox) VerifyReceiveReq(r *http.Request) (string, error) {
	var req struct {
		ID  string `json:"id"`
		TS  string `json:"ts"`
		Sig string `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return "", fmt.Errorf("invalid request %w", err)
	}

	id := req.ID
	ts := req.TS
	sig := req.Sig

	if id == "" || ts == "" || sig == "" {
		return "", fmt.Errorf("missing id, ts, or sig")
	}

	keys, exists := in.keyring.Get(id)
	if !exists {
		return "", fmt.Errorf("keys not found")
	}

	message := []byte(id + ts)
	pubKey, err := base64.StdEncoding.DecodeString(keys.EdPub)
	if err != nil {
		return "", fmt.Errorf("invalid public key")
	}

	valid, err := core.VerifySignature(pubKey, message, sig)
	if err != nil || !valid {
		return "", fmt.Errorf("invalid signature %w", err)
	}

	return id, nil
}
