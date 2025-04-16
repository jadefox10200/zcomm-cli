package main

import (
	"log"
	"net/http"
)

func main() {
	// Load persistent stores
	keyStore, err := NewKeyStore("data/pubkeys.json")
	if err != nil {
		log.Fatalf("Failed to load key store: %v", err)
	}

	identityStore, err := NewIdentityStore("data/identities.json")
	if err != nil {
		log.Fatalf("Failed to load identity store: %v", err)
	}

	// Initialize inbox handler
	inbox := NewInbox(keyStore)

	// Register HTTP routes
	http.HandleFunc("/identity", HandleIdentity(identityStore, keyStore))
	http.HandleFunc("/send", inbox.HandleSend)
	http.HandleFunc("/receive", inbox.HandleReceive)
	http.HandleFunc("/confirm", inbox.HandleConfirm)
	http.HandleFunc("/publish", HandlePublishKeys(keyStore))
	http.HandleFunc("/pubkey", HandleFetchKeys(keyStore))

	log.Println("ZComm Switchboard server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}