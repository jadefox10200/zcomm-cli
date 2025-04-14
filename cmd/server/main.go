package main

import (
	"log"
	"net/http"

	"github.com/jadefox10200/zcomm/server/handlers"
	"github.com/jadefox10200/zcomm/server/storage"
)

func main() {
	// Load persistent stores
	keyStore, err := storage.NewKeyStore("data/pubkeys.json")
	if err != nil {
		log.Fatalf("Failed to load key store: %v", err)
	}

	identityStore, err := storage.NewIdentityStore("data/identities.json")
	if err != nil {
		log.Fatalf("Failed to load identity store: %v", err)
	}

	// Register HTTP routes
	http.HandleFunc("/identity", handlers.HandleIdentity(identityStore, keyStore))
	http.HandleFunc("/send", handlers.HandleSend())
	http.HandleFunc("/receive", handlers.HandleReceive(keyStore))
	http.HandleFunc("/publish", handlers.HandlePublishKeys(keyStore))
	http.HandleFunc("/pubkey", handlers.HandleFetchKeys(keyStore))

	log.Println("ZComm Switchboard server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
