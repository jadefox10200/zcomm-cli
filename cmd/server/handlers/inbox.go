package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/jadefox10200/zcomm/core"
	"github.com/jadefox10200/zcomm/server/storage"
)

var inbox = make(map[string][]core.ZMessage)
var inboxMutex sync.Mutex

func HandleSend() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var msg core.ZMessage
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "invalid message", http.StatusBadRequest)
			return
		}
		inboxMutex.Lock()
		inbox[msg.To] = append(inbox[msg.To], msg)
		inboxMutex.Unlock()
		fmt.Fprintf(w, "Message delivered")
	}
}

func HandleReceive(keyStore *storage.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		ts := r.URL.Query().Get("ts")
		sig := r.URL.Query().Get("sig")

		keys, ok := keyStore.Get(id)
		if !ok {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		pubKeyBytes, err := base64.StdEncoding.DecodeString(keys.EdPub)
		if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
			http.Error(w, "Invalid public key", http.StatusInternalServerError)
			return
		}

		sigBytes, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			http.Error(w, "Invalid signature", http.StatusBadRequest)
			return
		}

		if !ed25519.Verify(pubKeyBytes, []byte(id+ts), sigBytes) {
			http.Error(w, "Unauthorized: signature verification failed", http.StatusUnauthorized)
			return
		}

		inboxMutex.Lock()
		defer inboxMutex.Unlock()
		msgs := inbox[id]
		if len(msgs) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		json.NewEncoder(w).Encode(msgs)
		inbox[id] = []core.ZMessage{}
	}
}
