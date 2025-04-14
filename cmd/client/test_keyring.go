package main

import (
	"fmt"
	"log"
)

func main() {
	keyringPath := "data/keyring.json"

	// Load or initialize the keyring
	kr, err := LoadKeyRing(keyringPath)
	if err != nil {
		log.Fatalf("Failed to load keyring: %v", err)
	}

	// Create a sample key entry
	entry := PublicKeyEntry{
		ID:       "alice",
		EdPub:    "alice-ed25519-pubkey",
		ECDHPub:  "alice-curve25519-pubkey",
		Verified: false,
	}

	// Add key to keyring
	if err := kr.AddKey(entry); err != nil {
		log.Fatalf("Failed to add key: %v", err)
	}
	fmt.Println("✅ Key added to keyring.")

	// Retrieve a key
	retrieved, ok := kr.GetKey("alice")
	if !ok {
		log.Fatalf("❌ Key not found for alice.")
	}
	fmt.Printf("🔑 Retrieved key for 'alice': %+v\n", retrieved)

	// List all keys
	fmt.Println("\n📜 All Keys in Keyring:")
	for _, e := range kr.AllKeys() {
		fmt.Printf("- ID: %s | Verified: %v | AddedAt: %d\n", e.ID, e.Verified, e.AddedAt)
	}
}
