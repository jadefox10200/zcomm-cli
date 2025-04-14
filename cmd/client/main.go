package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jadefox10200/zcomm/core"
)

func fetchRecipientKeys(id string) ([32]byte, error) {
	var pub [32]byte
	resp, err := http.Get("http://localhost:8080/pubkey?id=" + id)
	if err != nil {
		return pub, err
	}
	defer resp.Body.Close()

	var result core.PublicKeys
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return pub, err
	}

	raw, err := base64.StdEncoding.DecodeString(result.ECDHPub)
	if err != nil {
		return pub, err
	}
	copy(pub[:], raw)
	return pub, nil
}

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

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Failed to publish keys, server returned status: %s", resp.Status)
	}

	return nil
}

func checkForMessages(from string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) error {
	for {
		ts := fmt.Sprintf("%d", time.Now().Unix())
		message := []byte(from + ts)
		sig := ed25519.Sign(edPriv, message)
		sigB64 := base64.StdEncoding.EncodeToString(sig)
		encodedSig := url.QueryEscape(sigB64)
		url := fmt.Sprintf("http://localhost:8080/receive?id=%s&ts=%s&sig=%s", from, ts, encodedSig)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Println("Error fetching messages:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNoContent {
			time.Sleep(2 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			return fmt.Errorf("server returned error: %s", buf.String())
		}

		var msgs []core.ZMessage
		if err := json.NewDecoder(resp.Body).Decode(&msgs); err != nil {
			resp.Body.Close()
			return err
		}

		for _, msg := range msgs {
			fmt.Println("\nNew Message!")
			senderKeys, err := fetchRecipientKeys(msg.From)
			if err != nil {
				fmt.Println("Error fetching sender keys:", err)
				continue
			}

			sharedKey, err := core.DeriveSharedSecret(ecdhPriv, senderKeys)
			if err != nil {
				fmt.Println("Error deriving shared key:", err)
				continue
			}

			plaintext, err := msg.DecryptBody(sharedKey)
			if err != nil {
				fmt.Println("Error decrypting message:", err)
				continue
			}

			fmt.Printf("From %s\nMessage: %s\n", msg.From, plaintext)
		}

		time.Sleep(2 * time.Second)
	}
}

func printMenu() {
	fmt.Println("\nMain Menu")
	fmt.Println("1. Send Message")
	fmt.Println("2. View Inbox (IN)")
	fmt.Println("3. View Pending Messages")
	fmt.Println("4. View Sent Messages (OUT)")
	fmt.Println("5. Archive a Conversation")
	fmt.Println("6. Help")
	fmt.Println("7. Exit")
}

func main() {
	fromPtr := flag.String("from", "", "The sender's username (e.g., alice, bob, etc.)")
	flag.Parse()

	if *fromPtr == "" {
		fmt.Println("Usage: --from <sender>")
		os.Exit(1)
	}

	from := *fromPtr
	fmt.Printf("Client started for %s...\n", from)

	ks, edPriv, ecdhPriv, err := LoadOrCreateKeyPair(from)
	if err != nil {
		fmt.Println("Failed to load or create sender's keys:", err)
		os.Exit(1)
	}

	if err := publishKeys(ks); err != nil {
		fmt.Println("Failed to publish sender's public keys:", err)
		os.Exit(1)
	}
	fmt.Println("Successfully published sender's public keys.")

	go func() {
		if err := checkForMessages(from, edPriv, ecdhPriv); err != nil {
			fmt.Println("Error checking for messages:", err)
			os.Exit(1)
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	conversationHashes := make(map[string]string)

	for {
		printMenu()
		fmt.Print("Enter choice: ")
		if !scanner.Scan() {
			fmt.Println("Failed to read input")
			continue
		}

		switch scanner.Text() {
		case "1":
			fmt.Print("Enter recipient's username: ")
			if !scanner.Scan() {
				fmt.Println("Failed to read recipient")
				continue
			}
			to := scanner.Text()

			fmt.Print("Enter your message: ")
			reader := bufio.NewReader(os.Stdin)
			body, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println("Error reading message:", err)
				continue
			}
			body = strings.TrimSpace(body)

			recipientPubKey, err := fetchRecipientKeys(to)
			if err != nil {
				fmt.Println("Failed to fetch recipient's public key:", err)
				continue
			}

			sharedKey, err := core.DeriveSharedSecret(ecdhPriv, recipientPubKey)
			if err != nil {
				fmt.Println("Failed to derive shared secret:", err)
				continue
			}

			prevHash := conversationHashes[to]
			msg, err := core.NewEncryptedMessage(from, to, "text", body, edPriv, sharedKey, prevHash)
			if err != nil {
				fmt.Println("Failed to create message:", err)
				continue
			}

			conversationHashes[to] = msg.Hash
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

		case "2":
			ViewBasket("IN", LoadInboxMessages)
		case "3":
			ViewBasket("PENDING", LoadPendingMessages)
		case "4":
			ViewBasket("OUT", LoadSentMessages)
		case "5":
			fmt.Println("(Archive stub)")
		case "6":
			printMenu()
		case "7":
			fmt.Println("Exiting Zcomm. Goodbye!")
			return
		default:
			fmt.Println("Invalid choice. Type '6' for help.")
		}
	}
}

func ViewBasket(label string, loader func() ([]core.ZMessage, error)) {
	fmt.Printf("=== %s Messages ===\n", strings.Title(label))
	messages, err := loader()
	if err != nil {
		fmt.Printf("Error loading %s messages: %v\n", label, err)
		return
	}
	if len(messages) == 0 {
		fmt.Printf("No messages in %s.\n", label)
		return
	}
	for i, msg := range messages {
		fmt.Printf("[%d] From: %s | To: %s | Type: %s | Timestamp: %d\n",
			i+1, msg.From, msg.To, msg.Type, msg.Timestamp)
	}
}