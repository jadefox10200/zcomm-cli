package main 

import (
	"fmt"
	"log"
	"net/http"
	"encoding/base64"
	"encoding/json"
	"github.com/jadefox10200/zcomm/core"
)

func verifyNotification(req core.Notification, keys core.PublicKeys) error {
    if req.DispatchID == "" || req.Timestamp == 0 || req.Signature == "" {
        log.Printf("Missing fields in notification %s", req.UUID)
        return fmt.Errorf("missing fields")
    }
    pubKeyNotif, err := base64.StdEncoding.DecodeString(req.PubKey)
    if err != nil {
        log.Printf("Invalid public key in notification %s: %v", req.UUID, err)
        return fmt.Errorf("invalid public key")
    }
    pubKeyStored, err := base64.StdEncoding.DecodeString(keys.EdPub)
    if err != nil {		
        log.Printf("Invalid stored public key for %s: %v", req.From, err)
        return fmt.Errorf("invalid public key")
    }
    if string(pubKeyStored) != string(pubKeyNotif) {
        log.Printf("Public key mismatch for notification %s: stored=%s, notif=%s", req.UUID, keys.EdPub, req.PubKey)
        return fmt.Errorf("public key mismatch")
    }
    data := []byte(fmt.Sprintf("%s%d", req.UUID, req.Timestamp))
    valid, err := core.VerifySignature(pubKeyNotif, data, req.Signature)
    if err != nil || !valid {	
        log.Printf("Invalid signature for notification %s: err=%v, valid=%v", req.UUID, err, valid)
        return fmt.Errorf("invalid signature")
    }
    return nil  
}

func (in *Inbox) VerifyReceiveReq(r *http.Request) (string, error) {
	var req struct {
		ID  string `json:"id"`
		TS  string `json:"ts"`
		Sig string `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return "",fmt.Errorf("invalid request %w", err )
	}

	id := req.ID
	ts := req.TS
	sig := req.Sig

	if id == "" || ts == "" || sig == "" {
		return "",fmt.Errorf("missing id, ts, or sig")
	}

	keys, exists := in.keyring.Get(id)
	if !exists {
		return "",fmt.Errorf("keys not found")
	}

	message := []byte(id + ts)
	pubKey, err := base64.StdEncoding.DecodeString(keys.EdPub)
	if err != nil {
		return "", fmt.Errorf("invalid public keyd")
	}

	valid, err := core.VerifySignature(pubKey, message, sig)
	if err != nil || !valid {
		return "", fmt.Errorf("invalid signature %w", err)
	}

	return id, nil 
}