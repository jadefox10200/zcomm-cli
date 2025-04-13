package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/jadefox10200/zcomm/core"
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
func publishKeys(ks *KeyStore) error {
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
	// Parse command-line arguments
	fromPtr := flag.String("from", "", "The sender's username (e.g., alice, bob, etc.)")
	toPtr := flag.String("to", "", "The recipient's username (e.g., bob, alice, etc.)")
	bodyPtr := flag.String("body", "Hello!", "The message to send")
	flag.Parse()

	// Ensure sender and recipient are provided
	if *fromPtr == "" || *toPtr == "" {
		fmt.Println("Usage: --from <sender> --to <recipient> --body <message>")
		os.Exit(1)
	}

	from := *fromPtr
	to := *toPtr
	body := *bodyPtr

	// Load or create the sender's keypair
	ks, edPriv, ecdhPriv, err := LoadOrCreateKeyPair(from)
	if err != nil {
		fmt.Println("Failed to load or create sender's keys:", err)
		os.Exit(1)
	}

	// Publish sender's public keys if not already published
	if err := publishKeys(ks); err != nil {
		fmt.Println("Failed to publish sender's public keys:", err)
		os.Exit(1)
	}
	fmt.Println("Successfully published sender's public keys.")

	// Fetch recipient's public ECDH key
	bobPubKey, err := fetchRecipientKeys(to)
	if err != nil {
		// Recipient's keys not found, so let's create and publish them
		fmt.Println("Recipient's keys not found, creating and publishing recipient's keys...")

		// Create recipient's keys
		ksRecipient, _, ecdhPrivRecipient, err := LoadOrCreateKeyPair(to)
		if err != nil {
			fmt.Println("Failed to load or create recipient's keys:", err)
			os.Exit(1)
		}

		// Publish recipient's keys to the server
		if err := publishKeys(ksRecipient); err != nil {
			fmt.Println("Failed to publish recipient's keys:", err)
			os.Exit(1)
		}
		fmt.Println("Successfully created and published recipient's keys.")

		// Now fetch recipient's public key again after creating it
		bobPubKey, err = fetchRecipientKeys(to)
		if err != nil {
			fmt.Println("Failed to fetch recipient's public key after creating it:", err)
			os.Exit(1)
		}
	}

	// Derive shared secret using sender's private ECDH and recipient's public ECDH
	sharedKey, err := core.DeriveSharedSecret(ecdhPriv, bobPubKey)
	if err != nil {
		fmt.Println("Failed to derive shared secret:", err)
		os.Exit(1)
	}

	// Create encrypted, signed message
	msg, err := core.NewEncryptedMessage(from, to, "text", body, edPriv, sharedKey)
	if err != nil {
		fmt.Println("Failed to create message:", err)
		os.Exit(1)
	}

	// Send message
	data, err := json.Marshal(msg)
	if err != nil {
		fmt.Println("Failed to serialize message:", err)
		os.Exit(1)
	}

	resp, err := http.Post("http://localhost:8080/send", "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("Failed to send message:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Println("Message sent:", resp.Status)
}
