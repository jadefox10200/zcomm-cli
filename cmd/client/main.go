// cmd/client/main.go
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jadefox10200/zcomm/core"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/term"
)

const serverURL = "https://localhost:8443"

// Initialize HTTP client with custom TLS configuration to accept self-signed certificates
func init() {
	// Create a custom HTTP client that accepts self-signed certificates
	http.DefaultClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // WARNING: Only for development with self-signed certs
			},
		},
	}
}

var storage Storage

type Account struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	ZIDs         []string `json:"zids"`
}

func loadAccount(username string) (*Account, error) {
	path := filepath.Join("data", "accounts", fmt.Sprintf("account_%s.json", username))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read account file: %w", err)
	}
	var account Account
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, fmt.Errorf("unmarshal account: %w", err)
	}
	return &account, nil
}

func saveAccount(account *Account) error {
	path := filepath.Join("data", "accounts", fmt.Sprintf("account_%s.json", account.Username))
	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal account: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create accounts dir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

func createAccount(username, password string) error {
	path := filepath.Join("data", "accounts", fmt.Sprintf("account_%s.json", username))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return fmt.Errorf("account already exists")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	hashStr := fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))

	account := &Account{
		Username:     username,
		PasswordHash: hashStr,
		ZIDs:         []string{},
	}
	return saveAccount(account)
}

func parsePasswordHash(hashStr string) ([]byte, []byte, error) {
	if hashStr == "" {
		return nil, nil, fmt.Errorf("empty hash string")
	}

	parts := strings.Split(hashStr, "$")
	if len(parts) != 6 {
		return nil, nil, fmt.Errorf("invalid hash format: expected 6 parts, got %d", len(parts))
	}
	if parts[1] != "argon2id" {
		return nil, nil, fmt.Errorf("invalid algorithm: expected argon2id, got %s", parts[1])
	}
	if parts[2] != "v=19" {
		return nil, nil, fmt.Errorf("invalid version: expected v=19, got %s", parts[2])
	}

	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return nil, nil, fmt.Errorf("invalid parameters: expected 3, got %d", len(params))
	}
	for _, param := range params {
		if !strings.HasPrefix(param, "m=") && !strings.HasPrefix(param, "t=") && !strings.HasPrefix(param, "p=") {
			return nil, nil, fmt.Errorf("invalid parameter format: %s", param)
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("decode salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("decode hash: %w", err)
	}

	return salt, hash, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func promptLogin() (string, ed25519.PrivateKey, [32]byte, []byte, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", nil, [32]byte{}, nil, fmt.Errorf("read password: %w", err)
	}
	password := string(passwordBytes)

	account, err := loadAccount(username)
	if err != nil {
		return "", nil, [32]byte{}, nil, fmt.Errorf("load account: %w", err)
	}

	salt, storedHash, err := parsePasswordHash(account.PasswordHash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parse password hash failed: %v\n", err)
		return "", nil, [32]byte{}, nil, fmt.Errorf("parse hash: %w", err)
	}
	derivedHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	if !bytesEqual(derivedHash, storedHash) {
		return "", nil, [32]byte{}, nil, fmt.Errorf("invalid password")
	}

	// Use a fixed-length salt for encryption key derivation
	fixedSalt := make([]byte, 16)
	copy(fixedSalt, []byte(username+"zcomm_salt"))
	encryptionKey := argon2.IDKey([]byte(password), fixedSalt, 3, 64*1024, 4, 32)
	if len(encryptionKey) != 32 {
		return "", nil, [32]byte{}, nil, fmt.Errorf("invalid encryption key size: got %d, expected 32", len(encryptionKey))
	}

	fmt.Println("Available ZIDs:")
	for i, zid := range account.ZIDs {
		fmt.Printf("%d. %s\n", i+1, zid)
	}
	fmt.Print("Select ZID number (0 to create new ZID): ")
	var choice int
	fmt.Scanln(&choice)

	var zid string
	if choice == 0 {
		identity, err := GenerateAndStoreNewIdentity(encryptionKey)
		if err != nil {
			return "", nil, [32]byte{}, nil, fmt.Errorf("create ZID: %w", err)
		}
		zid = identity.ID
		for _, existingZID := range account.ZIDs {
			if existingZID == zid {
				return "", nil, [32]byte{}, nil, fmt.Errorf("generated ZID %s already exists in account", zid)
			}
		}
		account.ZIDs = append(account.ZIDs, zid)
		if err := saveAccount(account); err != nil {
			return "", nil, [32]byte{}, nil, fmt.Errorf("save account: %w", err)
		}
		fmt.Printf("Created new ZID: %s\n", zid)
	} else if choice < 1 || choice > len(account.ZIDs) {
		return "", nil, [32]byte{}, nil, fmt.Errorf("invalid ZID selection")
	} else {
		zid = account.ZIDs[choice-1]
	}

	//THIS IS THE MAIN FUNCTION CALL TO START THE DB CONNECTION:
	storage, err = NewSQLiteStorage(zid)
	if err != nil {
		return "", nil, [32]byte{}, nil, fmt.Errorf("initialize storage for ZID %s: %w", zid, err)
	}

	is, err := LoadIdentity(getIdentityPath(zid))
	if err != nil {
		return "", nil, [32]byte{}, nil, fmt.Errorf("load identity: %w", err)
	}
	if is.identity == nil {
		return "", nil, [32]byte{}, nil, fmt.Errorf("identity for %s not found", zid)
	}
	edPriv, ecdhPriv, err := DecryptIdentity(is.identity, encryptionKey)
	if err != nil {
		return "", nil, [32]byte{}, nil, fmt.Errorf("decrypt identity: %w", err)
	}
	// fmt.Printf("Ed25519 private key length after decryption: %d\n", len(edPriv))

	return zid, edPriv, ecdhPriv, encryptionKey, nil
}

func fetchPublicKeys(zid string) (core.PublicKeys, error) {
	// fmt.Printf("Getting keys for %s\n", zid)
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

func fetchNotifications(zid, ts, sig string) ([]core.Notification, int, error) {
	reqData := core.ReceiveRequest{ID: zid, TS: ts, Sig: sig}
	data, err := json.Marshal(reqData)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", serverURL+"/notifications_request", bytes.NewReader(data))
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch notifications: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("server error: %s", string(body))
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil, resp.StatusCode, nil
	}

	var notifs []core.Notification
	if err := json.NewDecoder(resp.Body).Decode(&notifs); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode notifications: %w", err)
	}
	return notifs, resp.StatusCode, nil
}

func fetchDispatches(zid, ts, sig string) ([]core.Dispatch, int, error) {
	reqData := core.ReceiveRequest{ID: zid, TS: ts, Sig: sig}
	data, err := json.Marshal(reqData)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", serverURL+"/receive", bytes.NewReader(data))
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch dispatches: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("server error: %s", string(body))
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil, resp.StatusCode, nil
	}

	var disps []core.Dispatch
	if err := json.NewDecoder(resp.Body).Decode(&disps); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode dispatches: %w", err)
	}
	return disps, resp.StatusCode, nil
}

func decryptDispatch(disp *core.Dispatch, ecdhPriv [32]byte) error {
	ephemeralPub, err := base64.StdEncoding.DecodeString(disp.EphemeralPubKey)
	if err != nil {
		return fmt.Errorf("decode ephemeral key: %w", err)
	}
	var ephemeralPubKey [32]byte
	copy(ephemeralPubKey[:], ephemeralPub)

	sharedKey, err := core.DeriveSharedSecret(ecdhPriv, ephemeralPubKey)
	if err != nil {
		return fmt.Errorf("derive shared key: %w", err)
	}

	body, err := disp.DecryptBody(sharedKey)
	if err != nil {
		return fmt.Errorf("decrypt dispatch: %w", err)
	}
	disp.Body = body
	return nil
}

func storeDispatchAndUpdateConversation(zid string, disp core.Dispatch, dispatches []core.Dispatch, storage Storage, ecdhPriv [32]byte) error {
	localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

	plaintext := disp.Body
	if disp.Nonce != "" && disp.EphemeralPubKey != "" {
		if err := decryptDispatch(&disp, ecdhPriv); err != nil {
			return fmt.Errorf("decrypt received dispatch: %w", err)
		}
		plaintext = disp.Body
	}

	localCiphertext, localNonce, err := core.EncryptAESGCM(localKey[:], []byte(plaintext))
	if err != nil {
		return fmt.Errorf("encrypt for local storage: %w", err)
	}
	disp.Body = base64.StdEncoding.EncodeToString(localCiphertext)
	disp.LocalNonce = base64.StdEncoding.EncodeToString(localNonce)

	if err := storage.StoreDispatch(zid, disp); err != nil {
		return fmt.Errorf("store dispatch: %w", err)
	}

	// Load the specific conversation
	conv, err := storage.LoadConversation(zid, disp.ConversationID)
	if err != nil {
		return fmt.Errorf("load conversation %s: %w", disp.ConversationID, err)
	}

	// Determine the next sequence number
	seqNo := 1
	for _, entry := range conv.Dispatches {
		if entry.SeqNo >= seqNo {
			seqNo = entry.SeqNo + 1
		}
	}

	// Store or update the conversation with the dispatch and Ended status
	if err := storage.StoreConversation(zid, disp.ConversationID, disp.UUID, seqNo, disp.Subject, disp.IsEnd); err != nil {
		return fmt.Errorf("store conversation: %w", err)
	}

	if err := storage.StoreBasket(zid, "inbox", disp.UUID); err != nil {
		return fmt.Errorf("store in inbox: %w", err)
	}

	//this logic sucks:
	//implement a dispatch linked list approach.
	unanswered, err := storage.LoadBasket(zid, "unanswered")
	if err != nil {
		return fmt.Errorf("load unanswered: %w", err)
	}
	for _, unansweredID := range unanswered {
		for _, unansweredDisp := range dispatches {
			if unansweredDisp.UUID == unansweredID && unansweredDisp.ConversationID == disp.ConversationID && unansweredDisp.To == disp.From {
				if err := storage.RemoveMessage(zid, "unanswered", unansweredID); err != nil {
					return fmt.Errorf("remove from unanswered: %w", err)
				}
				fmt.Printf("Removed dispatch %s from unanswered\n", unansweredID)
			}
		}
	}

	return nil
}

func checkForMessages(zid string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte, encryptionKey []byte) {
	backoff := 5 * time.Second
	maxBackoff := 60 * time.Second

	for {
		if err := processPendingNotifications(zid); err != nil {
			fmt.Fprintf(os.Stderr, "Process pending notifications: %v\n", err)
		}

		ts, sig, err := createReqSignature(zid, edPriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Create request signature: %v\n", err)
			time.Sleep(backoff)
			continue
		}

		dispatches, statusCode, err := fetchDispatches(zid, ts, sig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fetch dispatches: %v\n", err)
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		}

		if statusCode == http.StatusNoContent {
			backoff = 5 * time.Second
			time.Sleep(backoff)
			continue
		}

		if statusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "Server error: status %d\n", statusCode)
			time.Sleep(backoff)
			continue
		}

		//why do we need to load all dispatches?
		localDispatches, err := storage.LoadDispatches(zid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
			continue
		}

		for _, disp := range dispatches {
			fmt.Printf("Received dispatch from %s at %d\n", disp.From, disp.Timestamp)
			keys, err := fetchPublicKeys(disp.From)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Fetch sender keys for %s: %v\n", disp.From, err)
				continue
			}

			valid, err := verifyDispatch(disp, keys)
			if !valid || err != nil {
				fmt.Fprintf(os.Stderr, "Verification failed for dispatch from %s: %v\n", disp.From, err)
				continue
			}

			if err := storeDispatchAndUpdateConversation(zid, disp, localDispatches, storage, ecdhPriv); err != nil {
				fmt.Fprintf(os.Stderr, "Store dispatch from %s: %v\n", disp.From, err)
				continue
			}
			fmt.Println("Sending delivery notification")
			handleSendDelivery(disp, zid, edPriv, encryptionKey)
		}

		backoff = 5 * time.Second
		time.Sleep(backoff)
	}
}

// handleSendDelivery sends a delivery notification for a dispatch.
func handleSendDelivery(disp core.Dispatch, zid string, edPriv ed25519.PrivateKey, encryptionKey []byte) {
	// fmt.Printf("Ed25519 private key length before signing notification: %d\n", len(edPriv))
	identity, err := LoadIdentity(getIdentityPath(zid))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load identity: %v\n", err)
		return
	}
	if identity.identity == nil {
		fmt.Fprintf(os.Stderr, "Identity not initialized for %s\n", zid)
		return
	}

	deliveryReceipt := &core.Notification{
		UUID:       uuid.New().String(),
		DispatchID: disp.UUID,
		From:       zid,
		To:         disp.From,
		Type:       "delivery",
		Timestamp:  time.Now().Unix(),
	}

	// Log notification before signing
	// notifJSON, _ := json.MarshalIndent(deliveryReceipt, "", "  ")
	// fmt.Printf("Notification before signing: %s\n", notifJSON)

	err = core.SignNotification(deliveryReceipt, edPriv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign notification: %v\n", err)
		return
	}

	// Log notification after signing
	// notifJSON, _ = json.MarshalIndent(deliveryReceipt, "", "  ")
	// fmt.Printf("Notification after signing: %s\n", notifJSON)

	data, err := json.Marshal(deliveryReceipt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal delivery receipt: %v\n", err)
		return
	}

	resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
	if err != nil {
		if err := storage.StorePendingNotification(zid, *deliveryReceipt); err != nil {
			fmt.Fprintf(os.Stderr, "Store pending notification: %v\n", err)
		} else {
			fmt.Println("Stored delivery notification for later due to network error")
		}
		return
	}
	defer resp.Body.Close()

	// Log response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read response body: %v\n", err)
	} else if resp.StatusCode != http.StatusOK {
		fmt.Printf("Server response body: %s\n", body)
	}

	if resp.StatusCode != http.StatusOK {
		if err := storage.StorePendingNotification(zid, *deliveryReceipt); err != nil {
			fmt.Fprintf(os.Stderr, "Store pending notification: %v\n", err)
		} else {
			fmt.Printf("Stored delivery notification for later: server returned %d\n", resp.StatusCode)
		}
		return
	}
	fmt.Println("Delivery notification sent successfully")
}

// handleSendRead sends a read notification for a dispatch.
func handleSendRead(disp core.Dispatch, zid string, edPriv ed25519.PrivateKey, encryptionKey []byte) {
	fmt.Printf("Ed25519 private key length before signing read receipt: %d\n", len(edPriv))
	identity, err := LoadIdentity(getIdentityPath(zid))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't load identity for read receipt: %v\n", err)
		return
	}
	if identity.identity == nil {
		fmt.Fprintf(os.Stderr, "Identity not initialized for %s\n", zid)
		return
	}

	readReceipt := &core.Notification{
		UUID:       uuid.New().String(),
		DispatchID: disp.UUID,
		From:       zid,
		To:         disp.From,
		Type:       "read",
		Timestamp:  time.Now().Unix(),
	}

	// Log notification before signing
	// notifJSON, _ := json.MarshalIndent(readReceipt, "", "  ")
	// fmt.Printf("Read receipt before signing: %s\n", notifJSON)

	err = core.SignNotification(readReceipt, edPriv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign read receipt: %v\n", err)
		return
	}

	// Log notification after signing
	// notifJSON, _ = json.MarshalIndent(readReceipt, "", "  ")
	// fmt.Printf("Read receipt after signing: %s\n", notifJSON)

	if err := storage.StoreReadReceipt(zid, *readReceipt); err != nil {
		fmt.Fprintf(os.Stderr, "Store read receipt: %v\n", err)
		return
	}

	data, err := json.Marshal(readReceipt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal read receipt: %v\n", err)
		return
	}
	resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
	if err != nil || resp.StatusCode != http.StatusOK {
		if err := storage.StorePendingNotification(zid, *readReceipt); err != nil {
			fmt.Fprintf(os.Stderr, "Queue read receipt: %v\n", err)
		} else {
			fmt.Printf("Read receipt queued due to %v\n", err)
		}
		if resp != nil {
			// Log response body
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Read response body: %v\n", err)
			} else {
				fmt.Printf("Server response body: %s\n", body)
			}
			resp.Body.Close()
		}
	} else {
		fmt.Println("Read receipt sent successfully")
		resp.Body.Close()
	}
}

// handleIncomingNotifications processes incoming notifications.
func handleIncomingNotifications(zid string, notifs []core.Notification) {
	for _, notif := range notifs {
		// Retrieve public key from server
		keys, err := fetchPublicKeys(notif.From)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fetch public keys for %s: %v\n", notif.From, err)
			continue
		}
		pubKey, err := base64.StdEncoding.DecodeString(keys.EdPub)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Decode public key for %s: %v\n", notif.From, err)
			continue
		}

		// Log notification for verification
		// notifJSON, _ := json.MarshalIndent(notif, "", "  ")
		// fmt.Printf("Verifying notification: %s\n", notifJSON)

		valid, err := core.VerifyNotification(notif, pubKey)
		if !valid || err != nil {
			fmt.Fprintf(os.Stderr, "Invalid signature for notification %s from %s: %v\n", notif.UUID, notif.From, err)
			continue
		}

		// Fetch the dispatch directly from the database
		thisDisp, err := storage.GetDispatch(notif.DispatchID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Get dispatch %s for notification %s: %v\n", notif.DispatchID, notif.UUID, err)
			continue
		}

		switch notif.Type {
		case "delivery":
			err := updateDeliveredDispatch(zid, notif.DispatchID, thisDisp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Update delivered: %v\n", err)
			}
		case "read":
			err = storage.StoreReadReceipt(zid, notif)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Store read receipt: %v\n", err)
			}
		case "decline":
			// Archive the conversation
			err = storage.StoreConversation(zid, thisDisp.ConversationID, "", 0, thisDisp.Subject, true)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Archive conversation %s: %v\n", thisDisp.ConversationID, err)
				continue
			}

			// Remove dispatch from UNANSWERED or PENDING basket
			basket := "unanswered"
			err = storage.RemoveMessage(zid, basket, thisDisp.UUID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Remove dispatch %s from %s: %v\n", thisDisp.UUID, basket, err)
				// Continue to try other baskets
			}

			fmt.Printf("Dispatch %s declined by %s, conversation %s archived\n", notif.DispatchID, notif.From, thisDisp.ConversationID)
		}
	}
}

func updateDeliveredDispatch(zid, dispID string, disp core.Dispatch) error {
	if disp.IsEnd {
		if err := storage.RemoveMessage(zid, "out", dispID); err != nil {
			return fmt.Errorf("remove from out: %w", err)
		}
	} else {
		if err := storage.MoveMessage(zid, "out", "unanswered", dispID); err != nil {
			return fmt.Errorf("move to unanswered: %w", err)
		}
	}
	fmt.Printf("Dispatch %s confirmed delivered\n", dispID)
	return nil
}

func pollNotifications(zid string, edPriv ed25519.PrivateKey) {
	for {
		ts, sig, err := createReqSignature(zid, edPriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Create request signature: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		notifications, _, err := fetchNotifications(zid, ts, sig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fetch notifications: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		handleIncomingNotifications(zid, notifications)
		time.Sleep(5 * time.Second)
	}
}

func createAndSendDispatch(zid, recipient, subject, body, conversationID string, edPriv ed25519.PrivateKey, encryptionKey []byte, isEnd bool, storage Storage) error {
	is, err := LoadIdentity(filepath.Join("data", "identities", fmt.Sprintf("identity_%s.json", zid)))
	if err != nil {
		return fmt.Errorf("load identity: %v", err)
	}
	if is.identity == nil {
		return fmt.Errorf("identity for %s not found", zid)
	}
	identity := is.identity

	keys, err := fetchPublicKeys(recipient)
	if err != nil {
		return fmt.Errorf("fetch recipient keys: %w", err)
	}

	ecdhPub, err := base64.StdEncoding.DecodeString(keys.ECDHPub)
	if err != nil {
		return fmt.Errorf("decode ecdh key: %w", err)
	}
	var ecdhPubKey [32]byte
	copy(ecdhPubKey[:], ecdhPub)

	var ephemeralPriv [32]byte
	if _, err := rand.Read(ephemeralPriv[:]); err != nil {
		return fmt.Errorf("generate ephemeral key: %w", err)
	}

	ephemeralPub, err := curve25519.X25519(ephemeralPriv[:], curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("generate ephemeral public key: %w", err)
	}

	var sharedKey [32]byte
	shared, err := curve25519.X25519(ephemeralPriv[:], ecdhPubKey[:])
	if err != nil {
		return fmt.Errorf("derive shared key: %w", err)
	}
	copy(sharedKey[:], shared)

	disp, err := core.NewEncryptedDispatch(zid, recipient, nil, nil, subject, body, conversationID, edPriv, sharedKey, ephemeralPub, isEnd)
	if err != nil {
		return fmt.Errorf("create dispatch: %w", err)
	}

	localDisp := *disp

	if len(encryptionKey) != 32 {
		return fmt.Errorf("invalid encryption key size: got %d, expected 32", len(encryptionKey))
	}

	edPrivNew, ecdhPriv, err := DecryptIdentity(identity, encryptionKey)
	if err != nil {
		return fmt.Errorf("decrypt identity for local storage: %w", err)
	}
	_ = edPrivNew // Not used for local storage encryption

	localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

	localCiphertext, localNonce, err := core.EncryptAESGCM(localKey[:], []byte(body))
	if err != nil {
		return fmt.Errorf("encrypt body for local storage: %w", err)
	}

	localDisp.Body = base64.StdEncoding.EncodeToString(localCiphertext)
	localDisp.LocalNonce = base64.StdEncoding.EncodeToString(localNonce)

	if err := storage.StoreDispatch(zid, localDisp); err != nil {
		return fmt.Errorf("store dispatch: %w", err)
	}
	if err := storage.StoreBasket(zid, "out", localDisp.UUID); err != nil {
		return fmt.Errorf("store out: %w", err)
	}

	// Load the specific conversation. Use the ConversationID from the Dispatch as this may might be a new Conversation.
	//if this is new, conv will be empty
	conv, err := storage.LoadConversation(zid, disp.ConversationID)
	if err != nil {
		return fmt.Errorf("load conversation %s: %w", conversationID, err)
	}

	// Determine the next sequence number
	//this doesn't work:
	seqNo := 1
	for _, entry := range conv.Dispatches {
		if entry.SeqNo >= seqNo {
			seqNo = entry.SeqNo + 1
		}
	}

	// Store or update the conversation with the dispatch and Ended status
	if err := storage.StoreConversation(zid, disp.ConversationID, localDisp.UUID, seqNo, subject, isEnd); err != nil {
		return fmt.Errorf("store conversation: %w", err)
	}

	data, err := json.Marshal(disp)
	if err != nil {
		return fmt.Errorf("marshal dispatch: %w", err)
	}

	resp, err := http.Post(serverURL+"/send", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("send dispatch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("send dispatch failed: %s", string(body))
	}
	return nil
}

func handleAnswer(zid string, disp core.Dispatch, basket string, edPriv ed25519.PrivateKey, encryptionKey []byte, isEnd bool) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Reply body: ")
	body, _ := reader.ReadString('\n')
	body = strings.TrimSpace(body)

	if err := createAndSendDispatch(zid, disp.From, disp.Subject, body, disp.ConversationID, edPriv, encryptionKey, isEnd, storage); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return false
	}

	fmt.Printf("About to remove basket: %v\n", basket)
	if err := storage.RemoveMessage(zid, basket, disp.UUID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove original: %v\n", err)
		return false
	}

	fmt.Printf("Reply sent to %s\n", disp.From)
	return true
}

func handlePending(zid, basket, dispID string) bool {
	if basket != "pending" {
		if err := storage.MoveMessage(zid, basket, "pending", dispID); err != nil {
			fmt.Fprintf(os.Stderr, "Move to pending: %v\n", err)
			return false
		}
		fmt.Println("Dispatch moved to pending")
		return true
	}
	return false
}

// this function is used solely to delete an ack:
// updating the conversation status to Ended should happen at some point before this function
func handleACK(zid, basket, dispID string, isEnd bool) bool {
	if !isEnd {
		fmt.Println("Only ACK dispatches can be removed with this option")
		return false
	}
	if err := storage.RemoveMessage(zid, basket, dispID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove ACK dispatch: %v\n", err)
		return false
	}
	fmt.Println("ACK dispatch removed")
	return true
}

func handleExit() bool {
	return false
}

func displayDispatch(zid string, disp core.Dispatch, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) {
	localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

	var body string
	if disp.LocalNonce != "" {
		ciphertext, err := base64.StdEncoding.DecodeString(disp.Body)
		if err != nil {
			body = fmt.Sprintf("%s (failed to decode body: %v)", disp.Body, err)
		} else {
			nonce, err := base64.StdEncoding.DecodeString(disp.LocalNonce)
			if err != nil {
				body = fmt.Sprintf("%s (failed to decode local nonce: %v)", disp.Body, err)
			} else {
				plaintext, err := core.DecryptAESGCM(localKey[:], nonce, ciphertext)
				if err != nil {
					body = fmt.Sprintf("%s (local decryption failed: %v)", disp.Body, err)
				} else {
					body = string(plaintext)
				}
			}
		}
	} else {
		if disp.Nonce != "" && disp.EphemeralPubKey != "" {
			err := decryptDispatch(&disp, ecdhPriv)
			if err != nil {
				body = fmt.Sprintf("%s (transmission decryption failed: %v)", disp.Body, err)
			} else {
				body = disp.Body
			}
		} else {
			body = disp.Body
		}
	}
	sender := disp.From
	if alias, err := storage.ResolveAlias(zid, disp.From); err == nil {
		sender = alias
	}

	fmt.Printf("To: %s From: %s\nSubject: %s", disp.To, sender, disp.Subject)
	if disp.IsEnd {
		fmt.Printf(" - ACK")
	}
	fmt.Printf("\nBody: %s\n", body)
}

func handleDispatchView(zid string, disp core.Dispatch, basket string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte, encryptionKey []byte) bool {

	displayDispatch(zid, disp, edPriv, ecdhPriv)
	if basket == "inbox" {
		handleSendRead(disp, zid, edPriv, encryptionKey)
		processed := handlePending(zid, "inbox", disp.UUID)
		if !processed {
			fmt.Println("Displayed but failed to process dispatch")
			return false
		}
		//since we moved the message we need to update the basket.
		basket = "pending"
	}

	fmt.Println("1. Answer")
	if disp.IsEnd {
		fmt.Println("2. Delete ACK")
	} else {
		fmt.Println("2. ACK")
	}
	fmt.Println("3. Decline to answer")
	fmt.Println("4. Exit")
	fmt.Print("Choose an option: ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		return handleAnswer(zid, disp, basket, edPriv, encryptionKey, false)
	case "2":
		if disp.IsEnd {
			return handleACK(zid, basket, disp.UUID, disp.IsEnd)
		}
		return handleAnswer(zid, disp, basket, edPriv, encryptionKey, true)
	case "3":
		return handleDecline(zid, disp, basket, edPriv, encryptionKey, storage)
	case "4":
		return handleExit()
	default:
		fmt.Println("Invalid option")
		return false
	}
}

func handleSendDispatch(zid string, edPriv ed25519.PrivateKey, encryptionKey []byte) {
	var found bool
	var recipient string
	for !found {
		fmt.Print("Enter recipient (alias/ZID or 0 to exit): ")
		fmt.Scanln(&recipient)

		// Resolve alias to ZID
		resolved, err := storage.ResolveAlias(zid, recipient)
		if err != nil {
			//if resolved == 0, user tried to exit this menu
			if resolved == "0" {
				return
			}
			fmt.Printf("Failed to resolve alias: %s", err.Error())
			continue
		}
		recipient = resolved
		fmt.Printf("Resolved: %s\n", recipient)
		found = true
	}

	fmt.Print("Enter subject: ")
	var subject string
	fmt.Scanln(&subject)
	fmt.Print("Enter body: ")
	var body string
	fmt.Scanln(&body)

	err := createAndSendDispatch(zid, recipient, subject, body, "", edPriv, encryptionKey, false, storage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Send dispatch: %v\n", err)
		return
	}
	fmt.Println("Dispatch sent")
}

// depreciate:
func sendNewDispatch(zid string, edPriv ed25519.PrivateKey, encryptionKey []byte) error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("To: ")
	to, _ := reader.ReadString('\n')
	to = strings.TrimSpace(to)
	fmt.Print("Subject: ")
	subject, _ := reader.ReadString('\n')
	subject = strings.TrimSpace(subject)
	fmt.Print("Body: ")
	body, _ := reader.ReadString('\n')
	body = strings.TrimSpace(body)

	if err := createAndSendDispatch(zid, to, subject, body, "", edPriv, encryptionKey, false, storage); err != nil {
		return err
	}
	fmt.Printf("Dispatch sent to %s\n", to)
	return nil
}

func selectDispatchFromBasket(zid, basket string) (core.Dispatch, bool) {
	disps, err := storage.LoadBasketDispatches(zid, basket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load basket: %v\n", err)
		return core.Dispatch{}, false
	}
	displayBasketDispatches(disps, basket)

	fmt.Print("Select dispatch number (0 to exit): ")
	var num int
	fmt.Scanln(&num)
	if num == 0 {
		return core.Dispatch{}, false
	}
	if num < 1 || num > len(disps) {
		fmt.Println("Invalid selection")
		return core.Dispatch{}, false
	}
	disp, err := storage.GetDispatch(disps[num-1].DispatchID)
	if err != nil {
		fmt.Printf("Failed to get dispatch: %v\n", err.Error())
		return core.Dispatch{}, false
	}

	return disp, true
}

func displayBasketDispatches(disps []core.BasketDispatch, basket string) {
	for k, v := range disps {
		if basket == "unanswered" {
			fmt.Printf("%d. To: %s, Subject: %s\n", k+1, v.From, v.Subject)
		} else {
			fmt.Printf("%d. To: %s, Subject: %s\n", k+1, v.To, v.Subject)
		}
	}
}

// func handleOutBasketDispatch(disp core.Dispatch) {
// 	fmt.Println("NEED TO IMPLEMENT OUTBASKET FUNCTIONS")
// 	//redundant return so we remember to to do this:
// 	return
// }

func viewBasket(zid, basket string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte, encryptionKey []byte) {
	disps, err := storage.LoadBasketDispatches(zid, basket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load basket: %v\n", err)
		return
	}
	if len(disps) == 0 {
		fmt.Println("No dispatches found")
		return
	}
	// displayBasketDispatches(disps)
	switch strings.ToLower(basket) {
	case "inbox", "pending":
		disp, ok := selectDispatchFromBasket(zid, basket)
		if !ok {
			return
		}
		if handleDispatchView(zid, disp, basket, edPriv, ecdhPriv, encryptionKey) {
			fmt.Println("Dispatch processed")
		}
	case "out":
		disp, ok := selectDispatchFromBasket(zid, basket)
		if !ok {
			return
		}
		displayDispatch(zid, disp, edPriv, ecdhPriv)
		storage.HandleOutBasketDispatch(zid, disp)
	case "unanswered":
		displayBasketDispatches(disps, basket)
		fmt.Print("Select dispatch number (0 to exit, -N to forget): ")
		var num int
		fmt.Scanln(&num)
		if num == 0 {
			return
		}

		if num < 0 {
			num = -num
			if num < 1 || num > len(disps) {
				fmt.Println("Invalid selection")
				return
			}
			disp := disps[num-1]
			if err := storage.RemoveMessage(zid, "unanswered", disp.DispatchID); err != nil {
				fmt.Fprintf(os.Stderr, "Forget dispatch: %v\n", err)
				return
			}
			fmt.Printf("Dispatch %s forgotten\n", disp.DispatchID)
			return
		}
		if num < 1 || num > len(disps) {
			fmt.Println("Invalid selection")
			return
		}

		selected, err := storage.GetDispatch(disps[num-1].DispatchID)
		if err != nil {
			fmt.Println("Couldn't find dispatch")
		}

		displayDispatch(zid, selected, edPriv, ecdhPriv)
		return
	default:
		fmt.Println("Invalid selection")
		return
	}
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("1. Login\n2. Create Account\nChoose an option: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var zid string
	var edPriv ed25519.PrivateKey
	var ecdhPriv [32]byte
	var encryptionKey []byte
	var err error

	//calling promptLogin starts the NewSQLStorage and populates the global variable
	if choice == "1" {
		zid, edPriv, ecdhPriv, encryptionKey, err = promptLogin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
			os.Exit(1)
		}
	} else if choice == "2" {
		fmt.Print("Username: ")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Read password: %v\n", err)
			os.Exit(1)
		}
		if err := createAccount(username, string(passwordBytes)); err != nil {
			fmt.Fprintf(os.Stderr, "Create account: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Account created. Please login.")
		zid, edPriv, ecdhPriv, encryptionKey, err = promptLogin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Invalid option\n")
		os.Exit(1)
	}

	// if err := initBaskets(zid); err != nil {
	// 	fmt.Fprintf(os.Stderr, "Initialize baskets: %v\n", err)
	// 	os.Exit(1)
	// }

	go checkForMessages(zid, edPriv, ecdhPriv, encryptionKey)
	go pollNotifications(zid, edPriv)

	reader = bufio.NewReader(os.Stdin)
	for {
		inIds, pendingIds, outIds, unansweredIds, err := LoadBasketCounts(zid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load baskets: %v\n", err)
		}

		fmt.Printf("ZID: %s\n", zid)
		fmt.Printf("\n1. Send Dispatch\n")
		fmt.Printf("2. View Inbox [%v]\n", inIds)
		fmt.Printf("3. View Pending [%v]\n", pendingIds)
		fmt.Printf("4. View Out [%v]\n", outIds)
		fmt.Printf("5. View Delivered [%v]\n", unansweredIds)
		fmt.Printf("6. View Conversations\n")
		fmt.Printf("7. View Archived Conversations\n")
		fmt.Printf("8. Manage Contacts\n")
		fmt.Printf("9. Exit\n")
		fmt.Print("Choose an option: ")

		choice, _ = reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			handleSendDispatch(zid, edPriv, encryptionKey)
			// if err := sendNewDispatch(zid, edPriv, encryptionKey); err != nil {
			// 	fmt.Fprintf(os.Stderr, "%v\n", err)
			// }
		case "2":
			viewBasket(zid, "inbox", edPriv, ecdhPriv, encryptionKey)
		case "3":
			viewBasket(zid, "pending", edPriv, ecdhPriv, encryptionKey)
		case "4":
			viewBasket(zid, "out", edPriv, ecdhPriv, encryptionKey)
		case "5":
			viewBasket(zid, "unanswered", edPriv, ecdhPriv, encryptionKey)
		case "6":
			storage.ViewConversations(zid, edPriv, ecdhPriv, encryptionKey, false)
		case "7":
			storage.ViewConversations(zid, edPriv, ecdhPriv, encryptionKey, true)
		case "8":
			handleContacts(zid, storage)
		case "9":
			os.Exit(0)
		default:
			fmt.Println("Invalid option")
		}
	}
}

func processPendingNotifications(zid string) error {
	notifs, err := storage.LoadPendingNotifications(zid)
	if err != nil {
		return fmt.Errorf("load pending notifications: %w", err)
	}
	if len(notifs) == 0 {
		return nil
	}

	for _, notif := range notifs {
		data, err := json.Marshal(notif)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Marshal pending notification %s: %v\n", notif.UUID, err)
			continue
		}
		resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Send pending notification %s: %v\n", notif.UUID, err)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "Send pending notification %s failed: %s\n", notif.UUID, resp.Status)
			continue
		}

		if err := storage.RemovePendingNotification(zid, notif.UUID, notif.Type); err != nil {
			fmt.Fprintf(os.Stderr, "Remove pending notification %s: %v\n", notif.UUID, err)
			continue
		}
		fmt.Printf("Sent queued %s notification %s\n", notif.Type, notif.UUID)
	}
	return nil
}

func LoadBasketCounts(zid string) (int, int, int, int, error) {
	inIds, err := storage.LoadBasket(zid, "inbox")
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("load in: %v", err)
	}
	pendingIds, err := storage.LoadBasket(zid, "pending")
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("load pending: %v", err)
	}
	outIds, err := storage.LoadBasket(zid, "out")
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("load out: %v", err)
	}
	unansweredIds, err := storage.LoadBasket(zid, "unanswered")
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("load unanswered: %v", err)
	}

	return len(inIds), len(pendingIds), len(outIds), len(unansweredIds), nil
}

func LoadBaskets(zid string) ([]string, []string, []string, []string, error) {
	inIds, err := storage.LoadBasket(zid, "inbox")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load in: %v", err)
	}
	pendingIds, err := storage.LoadBasket(zid, "pending")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load pending: %v", err)
	}
	outIds, err := storage.LoadBasket(zid, "out")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load out: %v", err)
	}
	unansweredIds, err := storage.LoadBasket(zid, "unanswered")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load unanswered: %v", err)
	}

	return inIds, pendingIds, outIds, unansweredIds, nil
}

func handleContacts(zid string, storage Storage) {
	for {
		fmt.Println("\nContact Management:")
		fmt.Println("1. Add Contact")
		fmt.Println("2. List Contacts")
		fmt.Println("3. Remove Contact")
		fmt.Println("4. Back")
		fmt.Print("Select an option: ")

		var choice string
		fmt.Scanln(&choice)

		switch choice {
		case "1":
			fmt.Print("Enter ZID: ")
			var contactZID string
			fmt.Scanln(&contactZID)

			fmt.Print("Enter alias: ")
			var alias string
			fmt.Scanln(&alias)

			// Fetch public keys from server
			keys, err := fetchPublicKeys(contactZID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Fetch public keys: %v\n", err)
				continue
			}

			err = storage.AddContact(zid, alias, contactZID, keys.EdPub, keys.ECDHPub)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Add contact: %v\n", err)
				continue
			}
			fmt.Printf("Contact %s added with ZID %s\n", alias, contactZID)

		case "2":
			contacts, err := storage.ListContacts(zid)
			if err != nil {
				fmt.Fprintf(os.Stderr, "List contacts: %v\n", err)
				continue
			}
			if len(contacts) == 0 {
				fmt.Println("No contacts found")
				continue
			}
			fmt.Println("\nContacts:")
			for _, c := range contacts {
				fmt.Printf("Alias: %s, ZID: %s, Last Updated: %s\n",
					c.Alias, c.ZID, time.Unix(c.LastUpdated, 0).Format(time.RFC3339))
			}

		case "3":
			fmt.Print("Enter alias to remove: ")
			var alias string
			fmt.Scanln(&alias)
			err := storage.RemoveContact(zid, alias)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Remove contact: %v\n", err)
				continue
			}
			fmt.Printf("Contact %s removed\n", alias)

		case "4":
			return

		default:
			fmt.Println("Invalid option")
		}
	}
}

func handleDecline(zid string, disp core.Dispatch, basket string, edPriv ed25519.PrivateKey, encryptionKey []byte, storage Storage) bool {
	notif := core.Notification{
		UUID:       uuid.New().String(),
		DispatchID: disp.UUID,
		From:       zid,
		To:         disp.From,
		Type:       "decline",
		Timestamp:  time.Now().Unix(),
	}

	if err := storage.RemoveMessage(zid, basket, disp.UUID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove dispatch: %v\n", err)
		return false
	}

	if err := core.SignNotification(&notif, edPriv); err != nil {
		fmt.Fprintf(os.Stderr, "Sign decline notification: %v\n", err)
		return false
	}

	data, err := json.Marshal(notif)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal delivery receipt: %v\n", err)
		return false
	}

	resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
	if err != nil {
		if err := storage.StorePendingNotification(zid, notif); err != nil {
			fmt.Fprintf(os.Stderr, "Store pending notification: %v\n", err)
		} else {
			fmt.Println("Stored delivery notification for later due to network error")
		}
		return false
	}
	defer resp.Body.Close()

	// Log response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read response body: %v\n", err)
	} else if resp.StatusCode != http.StatusOK {
		fmt.Printf("Server response body: %s\n", body)
	}

	if resp.StatusCode != http.StatusOK {
		if err := storage.StorePendingNotification(zid, notif); err != nil {
			fmt.Fprintf(os.Stderr, "Store pending decline notification: %v\n", err)
		} else {
			fmt.Printf("Stored decline notification for later: server returned %d\n", resp.StatusCode)
		}
		return false
	}
	fmt.Println("Delivery notification sent successfully")

	// if err := storage.StorePendingNotification(zid, notif); err != nil {
	// 	fmt.Fprintf(os.Stderr, "Store decline notification: %v\n", err)
	// 	return false
	// }

	// Archive conversation
	if err := storage.StoreConversation(zid, disp.ConversationID, "", 0, disp.Subject, true); err != nil {
		fmt.Fprintf(os.Stderr, "Archive conversation: %v\n", err)
		return false
	}

	// Remove from basket
	if err := storage.RemoveMessage(zid, basket, disp.UUID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove dispatch: %v\n", err)
		return false
	}

	fmt.Println("Dispatch declined and conversation archived")
	return true
}
