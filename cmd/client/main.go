package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

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

// Function to check for incoming messages
func checkForMessages(from string) error {
	for {
		resp, err := http.Get("http://localhost:8080/receive?to=" + from)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNoContent {
			// No new message, wait a bit and check again
			time.Sleep(2 * time.Second)
			continue
		}

		var result map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}

		fmt.Println("New message received:")
		// Decode the message and print it
		// Assuming the message has been encrypted and signed properly
		// In reality, you'd also need to decrypt here
		fmt.Println(result["body"])

		time.Sleep(2 * time.Second) // Check again every 2 seconds
	}
}

// Main entry point for sending a message
func main() {
	// Parse the 'from' flag for the sender's username
	fromPtr := flag.String("from", "", "The sender's username (e.g., alice, bob, etc.)")
	flag.Parse()

	// Ensure sender is provided
	if *fromPtr == "" {
		fmt.Println("Usage: --from <sender>")
		os.Exit(1)
	}

	from := *fromPtr
	fmt.Printf("Client started for %s...\n", from)

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

	// Start a goroutine to check for incoming messages
	go func() {
		if err := checkForMessages(from); err != nil {
			fmt.Println("Error checking for messages:", err)
			os.Exit(1)
		}
	}()

	// Main loop to allow the client to send messages
	for {
		fmt.Print("Enter recipient's username (or 'exit' to quit): ")
		var to string
		fmt.Scanln(&to)

		if to == "exit" {
			break
		}

		fmt.Print("Enter the message to send: ")
		var body string
		fmt.Scanln(&body)

		// Fetch recipient's public ECDH key
		recipientPubKey, err := fetchRecipientKeys(to)
		if err != nil {
			fmt.Println("Failed to fetch recipient's public key:", err)
			continue
		}

		// Derive shared secret using sender's private ECDH and recipient's public ECDH
		sharedKey, err := core.DeriveSharedSecret(ecdhPriv, recipientPubKey)
		if err != nil {
			fmt.Println("Failed to derive shared secret:", err)
			continue
		}

		// Create encrypted, signed message
		msg, err := core.NewEncryptedMessage(from, to, "text", body, edPriv, sharedKey)
		if err != nil {
			fmt.Println("Failed to create message:", err)
			continue
		}

		// Send message to the server
		data, err := json.Marshal(msg)
		if err != nil {
			fmt.Println("Failed to serialize message:", err)
			continue
		}

		resp, err := http.Post("http://localhost:8080/send", "application/json", bytes.NewBuffer(data))
		if err != nil {
			fmt.Println("Failed to send message:", err)
			continue
		}
		defer resp.Body.Close()

		fmt.Println("Message sent successfully!")
	}
}
