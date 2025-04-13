package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"zcomm/core"
)

// Function to get the public key of the recipient from the server
func fetchRecipientKeys(id string) ([32]byte, error) {
	var pub [32]byte
	resp, err := http.Get("http://localhost:8080/pubkey?id=" + id)
	if err != nil {
		return pub, err
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return pub, err
	}

	raw, err := base64.StdEncoding.DecodeString(result["ecdh_pub"])
	if err != nil {
		return pub, err
	}
	copy(pub[:], raw)
	return pub, nil
}

// Function to publish keys to the server (if they’re not already published)
func publishKeys(ks *core.KeyStore) error {
	data, err := json.Marshal(map[string]string{
		"id":       ks.ID,
		"ed_pub":   ks.EdPub,
		"ecdh_pub": ks.ECDHPub,
	})
	if err != nil {
		return err
	}

	resp, err := http.Post("http://localhost:8080/publish", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Main entry point for sending a message
func main() {
	from := "alice" // Use your username
	to := "bob"     // Recipient username
	body := "Hello Bob!"

	// Load or create Alice's keypair
	ks, edPriv, ecdhPriv, err := core.LoadOrCreateKeyPair(from)
	if err != nil {
		fmt.Println("Failed to load Alice's keys:", err)
		os.Exit(1)
	}

	// Publish Alice's public keys if not already published
	if err := publishKeys(ks); err != nil {
		fmt.Println("Failed to publish Alice's public keys:", err)
		os.Exit(1)
	}
	fmt.Println("Successfully published Alice's public keys.")

	// Fetch Bob's public ECDH key
	bobPubKey, err := fetchRecipientKeys(to)
	if err != nil {
		fmt.Println("Failed to fetch Bob's public key:", err)
		os.Exit(1)
	}

	// Derive shared secret using Alice's private ECDH and Bob's public ECDH
	sharedKey, err := core.DeriveSharedSecret(ecdhPriv, bobPubKey)
	if err != nil {
		fmt.Println("Failed to derive shared secret:", err)
		os.Exit(1)
	}

	// Create encrypted, signed message
	msg, err :=
