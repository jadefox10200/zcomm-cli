//cmd/client/main.go
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jadefox10200/zcomm/core"
	"golang.org/x/crypto/curve25519"
)

const serverURL = "http://localhost:8080"

var (
	conversationsMu sync.RWMutex
	conversations   = make(map[string]map[string][]string)
)

func fetchPublicKeys(zid string) (core.PublicKeys, error) {
	resp, err := http.Get(fmt.Sprintf("%s/pubkey?id=%s", serverURL, zid))
	if err != nil {
		return core.PublicKeys{}, fmt.Errorf("fetch keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return core.PublicKeys{}, fmt.Errorf("fetch keys failed: %s", string(body))
	}

	var keys core.PublicKeys
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return core.PublicKeys{}, fmt.Errorf("decode keys: %w", err)
	}
	return keys, nil
}

func loadConversations(zid string) error {
	path := filepath.Join(zid, "conversations.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read conversations: %w", err)
	}

	var convs map[string]map[string][]string
	if err := json.Unmarshal(data, &convs); err != nil {
		return fmt.Errorf("unmarshal conversations: %w", err)
	}

	conversationsMu.Lock()
	defer conversationsMu.Unlock()
	conversations[zid] = convs[zid]
	if conversations[zid] == nil {
		conversations[zid] = make(map[string][]string)
	}
	return nil
}

func saveConversations(zid string) error {
	path := filepath.Join(zid, "conversations.json")
	conversationsMu.RLock()
	defer conversationsMu.RUnlock()

	data, err := json.MarshalIndent(map[string]map[string][]string{zid: conversations[zid]}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal conversations: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create conversations dir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

func checkForMessages(zid string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) error {
	backoff := 5 * time.Second
	maxBackoff := 60 * time.Second
	for {
		ts := fmt.Sprintf("%d", time.Now().Unix())
		message := []byte(zid + ts)
		sig, err := core.Sign(message, edPriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Sign message: %v\n", err)
			time.Sleep(backoff)
			continue
		}

		type receiveRequest struct {
			ID  string `json:"id"`
			TS  string `json:"ts"`
			Sig string `json:"sig"`
		}
		reqData := receiveRequest{ID: zid, TS: ts, Sig: sig}
		data, err := json.Marshal(reqData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Marshal request: %v\n", err)
			time.Sleep(backoff)
			continue
		}

		req, err := http.NewRequest("POST", serverURL+"/receive", bytes.NewReader(data))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Create request: %v\n", err)
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching dispatches: %v\n", err)
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNoContent {
			backoff = 5 * time.Second
			time.Sleep(backoff)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			return fmt.Errorf("server error: %s", buf.String())
		}

		var disps []core.Dispatch
		if err := json.NewDecoder(resp.Body).Decode(&disps); err != nil {
			fmt.Fprintf(os.Stderr, "Decode dispatches error: %v\n", err)
			time.Sleep(backoff)
			continue
		}

		for _, disp := range disps {
			fmt.Printf("Received dispatch from %s at %d\n", disp.From, disp.Timestamp)
			keys, err := fetchPublicKeys(disp.From)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching sender keys: %v\n", err)
				continue
			}

			pubKey, err := base64.StdEncoding.DecodeString(keys.EdPub)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding public key: %v\n", err)
				continue
			}

			hashInput := fmt.Sprintf("%s%s%s%s%s%d%s%s", disp.From, strings.Join(append(disp.To, disp.CC...), ","), disp.Subject, disp.Body, disp.Nonce, disp.Timestamp, disp.ConversationID, disp.EphemeralPubKey)
			digest := sha256.Sum256([]byte(hashInput))
			valid, err := core.VerifySignature(pubKey, digest[:], disp.Signature)
			if err != nil || !valid {
				fmt.Fprintf(os.Stderr, "Invalid signature from %s: %v\n", disp.From, err)
				continue
			}

			ephemeralPub, err := base64.StdEncoding.DecodeString(disp.EphemeralPubKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding ephemeral key: %v\n", err)
				continue
			}
			var ephemeralPubKey [32]byte
			copy(ephemeralPubKey[:], ephemeralPub)

			sharedKey, err := core.DeriveSharedSecret(ecdhPriv, ephemeralPubKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error deriving shared key: %v\n", err)
				continue
			}

			body, err := disp.DecryptBody(sharedKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decrypting dispatch: %v\n", err)
				continue
			}
			disp.Body = body
			disp.Basket = "IN"

			if err := StoreInboxMessage(zid, disp); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to store inbox dispatch: %v\n", err)
				continue
			}
			fmt.Printf("Stored inbox dispatch from %s: %s\n", disp.From, disp.Body)

			kr, err := LoadKeyRing(filepath.Join(zid, "keyring.json"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load keyring: %v\n", err)
			} else {
				if err := kr.AddKey(PublicKeyEntry{
					ID:      disp.From,
					EdPub:   keys.EdPub,
					ECDHPub: keys.ECDHPub,
					AddedAt: time.Now().Unix(),
				}); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to add key to keyring: %v\n", err)
				}
				if err := SaveKeyRing(filepath.Join(zid, "keyring.json"), kr); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to save keyring: %v\n", err)
				}
			}

			conversationsMu.Lock()
			if conversations[zid] == nil {
				conversations[zid] = make(map[string][]string)
			}
			conversations[zid][disp.ConversationID] = append(conversations[zid][disp.ConversationID], fmt.Sprintf("disp_%d", disp.Timestamp))
			conversationsMu.Unlock()
			if err := saveConversations(zid); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to save conversations: %v\n", err)
			}
		}

		backoff = 5 * time.Second
		time.Sleep(backoff)
	}
}

func confirmDelivery(zid string, dispatch core.Dispatch, edPriv ed25519.PrivateKey) error {
	type confirmRequest struct {
		ID        string `json:"id"`
		Timestamp int64  `json:"timestamp"`
		ConvID    string `json:"conversationID"`
		Sig       string `json:"sig"`
	}
	message := []byte(fmt.Sprintf("%s%d%s", zid, dispatch.Timestamp, dispatch.ConversationID))
	sig, err := core.Sign(message, edPriv)
	if err != nil {
		return fmt.Errorf("sign confirm: %w", err)
	}

	reqData := confirmRequest{
		ID:        zid,
		Timestamp: dispatch.Timestamp,
		ConvID:    dispatch.ConversationID,
		Sig:       sig,
	}
	data, err := json.Marshal(reqData)
	if err != nil {
		return fmt.Errorf("marshal confirm: %w", err)
	}

	req, err := http.NewRequest("POST", serverURL+"/confirm", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create confirm request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send confirm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("confirm failed: %s", string(body))
	}
	return nil
}

func pollDelivery(zid string, edPriv ed25519.PrivateKey) error {
	backoff := 10 * time.Second
	for {
		dispatches, err := LoadOutMessages(zid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load out messages: %v\n", err)
			time.Sleep(backoff)
			continue
		}

		for _, disp := range dispatches {
			if err := confirmDelivery(zid, disp, edPriv); err != nil {
				fmt.Fprintf(os.Stderr, "Confirm delivery for %d: %v\n", disp.Timestamp, err)
				continue
			}
			if err := MoveMessage(zid, "out", "sent", disp); err != nil {
				fmt.Fprintf(os.Stderr, "Move to sent for %d: %v\n", disp.Timestamp, err)
				continue
			}
			fmt.Printf("Confirmed delivery for dispatch %d to %s, moved to SENT\n", disp.Timestamp, disp.To[0])
		}

		time.Sleep(backoff)
	}
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func main() {
	zid := flag.String("zid", "", "ZID for this client")
	flag.Parse()
	if *zid == "" {
		var err error
		*zid, err = promptNewOrLogin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get ZID: %v\n", err)
			os.Exit(1)
		}
	}

	is, err := LoadIdentity(filepath.Join("data", "identities", fmt.Sprintf("identity_%s.json", *zid)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load identity: %v\n", err)
		os.Exit(1)
	}
	if is.identity == nil {
		fmt.Fprintf(os.Stderr, "Identity for %s not found\n", *zid)
		os.Exit(1)
	}
	identity := is.identity

	edPriv, err := base64.StdEncoding.DecodeString(identity.EdPriv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decode ed private key: %v\n", err)
		os.Exit(1)
	}

	ecdhPrivBytes, err := base64.StdEncoding.DecodeString(identity.ECDHPriv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decode ecdh private key: %v\n", err)
		os.Exit(1)
	}
	var ecdhPriv [32]byte
	copy(ecdhPriv[:], ecdhPrivBytes)

	if err := loadConversations(*zid); err != nil {
		fmt.Fprintf(os.Stderr, "Load conversations: %v\n", err)
		os.Exit(1)
	}

	go func() {
		if err := checkForMessages(*zid, edPriv, ecdhPriv); err != nil {
			fmt.Fprintf(os.Stderr, "Check messages: %v\n", err)
		}
	}()

	go func() {
		if err := pollDelivery(*zid, edPriv); err != nil {
			fmt.Fprintf(os.Stderr, "Poll delivery: %v\n", err)
		}
	}()

	for {
		fmt.Println("\n=== Zcomm Client ===")
		fmt.Println("1. Send Dispatch")
		fmt.Println("2. View Inbox")
		fmt.Println("3. View Pending")
		fmt.Println("4. View Outbox")
		fmt.Println("5. Exit")
		fmt.Print("Enter choice: ")

		var choice string
		fmt.Scanln(&choice)

		switch strings.ToLower(choice) {
		case "1":
			fmt.Print("Enter recipient ZID: ")
			toID, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			toID = strings.TrimSpace(toID)

			fmt.Print("Enter subject: ")
			subject, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			subject = strings.TrimSpace(subject)

			fmt.Print("Enter dispatch body: ")
			body, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			body = strings.TrimSpace(body)

			keys, err := fetchPublicKeys(toID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Fetch recipient keys: %v\n", err)
				continue
			}
			fmt.Printf("Fetched keys for %s: EdPub=%s, ECDHPub=%s\n", toID, keys.EdPub, keys.ECDHPub)

			ecdhPub, err := base64.StdEncoding.DecodeString(keys.ECDHPub)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Decode recipient ecdh key: %v\n", err)
				continue
			}
			var ecdhPubKey [32]byte
			copy(ecdhPubKey[:], ecdhPub)

			var ephemeralPriv [32]byte
			if _, err := rand.Read(ephemeralPriv[:]); err != nil {
				fmt.Fprintf(os.Stderr, "Generate ephemeral key: %v\n", err)
				continue
			}

			ephemeralPub, err := curve25519.X25519(ephemeralPriv[:], curve25519.Basepoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Generate ephemeral public key: %v\n", err)
				continue
			}

			sharedKey, err := core.DeriveSharedSecret(ephemeralPriv, ecdhPubKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Derive shared key: %v\n", err)
				continue
			}

			disp, err := core.NewEncryptedDispatch(*zid, []string{toID}, nil, nil, subject, body, nil, edPriv, sharedKey, ephemeralPub, "")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Create dispatch: %v\n", err)
				continue
			}

			data, err := json.Marshal(disp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Marshal dispatch: %w", err)
				continue
			}

			resp, err := http.Post(serverURL+"/send", "application/json", bytes.NewReader(data))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Send dispatch: %v\n", err)
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				fmt.Fprintf(os.Stderr, "Send dispatch failed: %s\n", string(body))
				continue
			}

			disp.Basket = "OUT"
			if err := StoreOutMessage(*zid, *disp); err != nil {
				fmt.Fprintf(os.Stderr, "Store out dispatch: %v\n", err)
				continue
			}
			fmt.Printf("Stored dispatch to OUT for %s: %s\n", toID, body)

			conversationsMu.Lock()
			if conversations[*zid] == nil {
				conversations[*zid] = make(map[string][]string)
			}
			conversations[*zid][disp.ConversationID] = append(conversations[*zid][disp.ConversationID], fmt.Sprintf("disp_%d", disp.Timestamp))
			conversationsMu.Unlock()
			if err := saveConversations(*zid); err != nil {
				fmt.Fprintf(os.Stderr, "Save conversations: %v\n", err)
			}

			fmt.Println("Dispatch sent to OUT.")

		case "2":
			fmt.Println("=== Inbox Dispatches ===")
			dispatches, err := LoadInboxMessages(*zid)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Load inbox: %v\n", err)
				continue
			}
			if len(dispatches) == 0 {
				fmt.Println("No dispatches in inbox.")
				continue
			}
			for i, disp := range dispatches {
				fmt.Printf("[%d] From: %s | Subject: %s | Timestamp: %d\n", i+1, disp.From, disp.Subject, disp.Timestamp)
			}
			fmt.Print("Enter dispatch number to view (0 to skip): ")
			var num int
			fmt.Scanln(&num)
			if num > 0 && num <= len(dispatches) {
				disp := dispatches[num-1]
				fmt.Printf("From: %s\nSubject: %s\nBody: %s\n", disp.From, disp.Subject, disp.Body)
				if err := MoveMessage(*zid, "inbox", "pending", disp); err != nil {
					fmt.Fprintf(os.Stderr, "Move to pending: %v\n", err)
					continue
				}
				fmt.Println("Moved to PENDING.")
			}

		case "3":
			fmt.Println("=== Pending Dispatches ===")
			dispatches, err := LoadPendingMessages(*zid)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Load pending: %v\n", err)
				continue
			}
			if len(dispatches) == 0 {
				fmt.Println("No dispatches in pending.")
				continue
			}
			for i, disp := range dispatches {
				fmt.Printf("[%d] From: %s | Subject: %s | Timestamp: %d\n", i+1, disp.From, disp.Subject, disp.Timestamp)
			}

		case "4":
			fmt.Println("=== Outbox Dispatches ===")
			dispatches, err := LoadOutMessages(*zid)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Load outbox: %v\n", err)
				continue
			}
			if len(dispatches) == 0 {
				fmt.Println("No dispatches in outbox.")
				continue
			}
			for i, disp := range dispatches {
				fmt.Printf("[%d] To: %s | Subject: %s | Timestamp: %d\n", i+1, disp.To[0], disp.Subject, disp.Timestamp)
			}

		case "5":
			fmt.Println("Exiting...")
			os.Exit(0)

		default:
			fmt.Println("Invalid choice, please try again.")
		}
	}
}