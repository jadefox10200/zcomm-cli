package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/jadefox10200/zcomm/core"
)

func HandleIdentity(identityStore *IdentityStore, keyStore *KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var identity Identity
		if err := json.NewDecoder(r.Body).Decode(&identity); err != nil || identity.ID == "" {
			http.Error(w, "Invalid identity", http.StatusBadRequest)
			return
		}

		if err := identityStore.Add(identity); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}

		keyStore.Set(identity.ID, identity.ToPublicKeys())
		if err := keyStore.Save(); err != nil {
			http.Error(w, "Failed to save keys", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Identity registered")
	}
}

func HandlePubKey(keys *KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}

		keys, exists := keys.Get(id)
		if !exists {
			http.Error(w, "keys not found", http.StatusNotFound)
			return
		}

		data, err := json.Marshal(keys)
		if err != nil {
			http.Error(w, "failed to encode keys", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}
}

type Inbox struct {
	mu      sync.RWMutex
	inbox   map[string][]core.Dispatch
	keyring *KeyStore
}

func NewInbox(keyring *KeyStore) *Inbox {
	return &Inbox{
		inbox:   make(map[string][]core.Dispatch),
		keyring: keyring,
	}
}

func (in *Inbox) HandleSend(w http.ResponseWriter, r *http.Request) {
	var disp core.Dispatch
	if err := json.NewDecoder(r.Body).Decode(&disp); err != nil {
		http.Error(w, "invalid dispatch", http.StatusBadRequest)
		return
	}

	in.mu.Lock()
	defer in.mu.Unlock()

	recipients := append(disp.To, disp.CC...)
	for _, to := range recipients {
		if _, exists := in.keyring.Get(to); !exists {
			http.Error(w, fmt.Sprintf("recipient %s not found", to), http.StatusBadRequest)
			return
		}
		in.inbox[to] = append(in.inbox[to], disp)
	}
	fmt.Printf("Stored dispatch for %s from %s: %s\n", strings.Join(recipients, ","), disp.From, disp.Subject)

	w.WriteHeader(http.StatusOK)
}

func (in *Inbox) HandleReceive(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID  string `json:"id"`
		TS  string `json:"ts"`
		Sig string `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	id := req.ID
	ts := req.TS
	sig := req.Sig

	if id == "" || ts == "" || sig == "" {
		http.Error(w, "missing id, ts, or sig", http.StatusBadRequest)
		return
	}

	keys, exists := in.keyring.Get(id)
	if !exists {
		http.Error(w, "keys not found", http.StatusBadRequest)
		return
	}

	message := []byte(id + ts)
	pubKey, err := base64.StdEncoding.DecodeString(keys.EdPub)
	if err != nil {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}

	valid, err := core.VerifySignature(pubKey, message, sig)
	if err != nil || !valid {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	in.mu.Lock()
	defer in.mu.Unlock()

	disps := in.inbox[id]
	if len(disps) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	data, err := json.Marshal(disps)
	if err != nil {
		http.Error(w, "failed to encode dispatches", http.StatusInternalServerError)
		return
	}

	in.inbox[id] = nil
	fmt.Printf("Delivered %d dispatches to %s\n", len(disps), id)

	w.Write(data)
}

func (in *Inbox) HandleConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID        string `json:"id"`
		Timestamp int64  `json:"timestamp"`
		ConvID    string `json:"conversationID"`
		Sig       string `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if req.ID == "" || req.Timestamp == 0 || req.ConvID == "" || req.Sig == "" {
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}

	keys, exists := in.keyring.Get(req.ID)
	if !exists {
		http.Error(w, "keys not found", http.StatusBadRequest)
		return
	}

	message := []byte(fmt.Sprintf("%s%d%s", req.ID, req.Timestamp, req.ConvID))
	pubKey, err := base64.StdEncoding.DecodeString(keys.EdPub)
	if err != nil {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}

	valid, err := core.VerifySignature(pubKey, message, req.Sig)
	if err != nil || !valid {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	in.mu.Lock()
	defer in.mu.Unlock()

	for _, disp := range in.inbox[req.ID] {
		if disp.Timestamp == req.Timestamp && disp.ConversationID == req.ConvID {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	http.Error(w, "dispatch not found", http.StatusNotFound)
}