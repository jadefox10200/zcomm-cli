package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"encoding/base64"
	"crypto/ed25519"

	"github.com/jadefox10200/zcomm/core"
)

var inbox = make(map[string][]core.ZMessage)

func handleSend(w http.ResponseWriter, r *http.Request) {
	var msg core.ZMessage
	err := json.NewDecoder(r.Body).Decode(&msg)
	if err != nil {
		http.Error(w, "invalid message", http.StatusBadRequest)
		return
	}
	inbox[msg.To] = append(inbox[msg.To], msg)
	fmt.Fprintf(w, "Message delivered")
}

func handleReceive(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	ts := r.URL.Query().Get("ts")
	sig := r.URL.Query().Get("sig")

	userKeys, ok := pubKeyDirectory[id]
	if !ok {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(userKeys.EdPub)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		http.Error(w, "Invalid public key", http.StatusInternalServerError)
		return
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		http.Error(w, "Invalide signature format", http.StatusBadRequest)
		return
	}

	//Reconstruct the signed message:
	message := []byte(id + ts)

	if !ed25519.Verify(pubKeyBytes, message, sigBytes) {
		http.Error(w, "Unauthorized: signature verification failed", http.StatusUnauthorized)
		return
	}

	msgs := inbox[id]
	if len(msgs) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(msgs)
	inbox[id] = []core.ZMessage{} // clear inbox after delivery
}

func main() {
	http.HandleFunc("/send", handleSend)
	http.HandleFunc("/receive", handleReceive)
	
	http.HandleFunc("/publish", handlePublishKeys)
	http.HandleFunc("/pubkey", handleFetchKeys)


	log.Println("ZComm Switchboard server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
