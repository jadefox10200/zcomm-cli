//cmd/server/handlers.go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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

//this is when the client is sending us a dispatch:
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
		//this an in-memory inbox so we should do something to make sure we don't lose something.  
		in.inbox[to] = append(in.inbox[to], disp)
	}
	fmt.Printf("Stored dispatch for %s from %s: %s\n", strings.Join(recipients, ","), disp.From, disp.Subject)

	w.WriteHeader(http.StatusOK)
}

//client is requesting their dispatches
func (in *Inbox) HandleReceive(w http.ResponseWriter, r *http.Request) {
	
	zid, err := in.VerifyReceiveReq(r)
	if err != nil {
		http.Error(w, "failed to verify you", http.StatusBadRequest)
		return 
	}

	in.mu.Lock()
	defer in.mu.Unlock()

	//get all of the dispatches for the client if any
	disps := in.inbox[zid]
	if len(disps) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	data, err := json.Marshal(disps)
	if err != nil {
		http.Error(w, "failed to encode dispatches", http.StatusInternalServerError)
		return
	}

	in.inbox[zid] = nil
	fmt.Printf("Delivered %d dispatches to %s\n", len(disps), zid)

	w.Write(data)
}

//client is requesting their notifications
func (in *Inbox) HandleReqNotifs(w http.ResponseWriter, r *http.Request) {
	
	//verify the client is who they say they are:
	zid, err := in.VerifyReceiveReq(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return 
	}

	in.mu.Lock()
	defer in.mu.Unlock()

	//get all of the dispatches for the client if any
	notifs := in.notifications[zid]
	if len(notifs) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	data, err := json.Marshal(notifs)
	if err != nil {
		http.Error(w, "failed to encode dispatches", http.StatusInternalServerError)
		return
	}

	in.notifications[zid] = nil
	fmt.Printf("Delivered %d notifications to %s\n", len(notifs), zid)

	w.Write(data)
}

//client is sending us a confirmation Notification of either delivered or read.
func (in *Inbox) HandleConfirm(w http.ResponseWriter, r *http.Request) {
	var req core.Notification
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	keys, found :=in.keyring.Get(req.From)
	if !found {
		http.Error(w, "couldn't find your keys", http.StatusBadRequest)
		return 
	}
	//verify this is a valid confirmation request
	err := verifyNotification(req, keys)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//prepare to store notification
	in.mu.Lock()
	defer in.mu.Unlock()

	if in.notifications == nil {
		in.notifications = make(map[string][]core.Notification)
	}

	//store the notifications by who they need to be sent to:
	if in.notifications[req.To] == nil {
		in.notifications[req.To] = make([]core.Notification, 0)
	}

	// Avoid duplicates
	for _, notif := range in.notifications[req.To] {
		if notif.UUID == req.UUID {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	//store notification by toID and send back HTTP STATUS OK
	in.notifications[req.To] = append(in.notifications[req.To], req)
	w.WriteHeader(http.StatusOK)
}

func HandlePublishKeys(store *KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var keys core.PublicKeys
		if err := json.NewDecoder(r.Body).Decode(&keys); err != nil {
			http.Error(w, "invalid key data", http.StatusBadRequest)
			return
		}
		store.Set(keys.ID, keys)
		if err := store.Save(); err != nil {
			http.Error(w, "failed to save keys", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleFetchKeys(store *KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		keys, ok := store.Get(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(keys)
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