// cmd/client/main.go
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jadefox10200/zcomm/core"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/term"
)

const serverURL = "https://localhost:8443"

// App holds the application state, including cryptographic keys and storage.
type App struct {
	mu            sync.RWMutex
	ZID           string
	EdPriv        ed25519.PrivateKey
	ECDHPriv      [32]byte
	EncryptionKey []byte
	Storage       Storage

	// Cache for online status
	lastOnlineCheck time.Time
	isOnlineCached  bool
}

// NewApp initializes a new App instance after successful login.
func NewApp(zid string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte, encryptionKey []byte, storage Storage) *App {
	return &App{
		ZID:           zid,
		EdPriv:        edPriv,
		ECDHPriv:      ecdhPriv,
		EncryptionKey: encryptionKey,
		Storage:       storage,
	}
}

// ClearKeys zeroes sensitive cryptographic keys in memory.
func (app *App) ClearKeys() {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.EdPriv != nil {
		for i := range app.EdPriv {
			app.EdPriv[i] = 0
		}
		app.EdPriv = nil
	}
	for i := range app.ECDHPriv {
		app.ECDHPriv[i] = 0
	}
	for i := range app.EncryptionKey {
		app.EncryptionKey[i] = 0
	}
}

// Logout clears sensitive data and closes storage.
func (app *App) Logout() error {
	app.ClearKeys()
	if s, ok := app.Storage.(*SQLiteStorage); ok {
		return s.db.Close()
	}
	return nil
}

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

func promptLogin() (*App, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	password := string(passwordBytes)

	account, err := loadAccount(username)
	if err != nil {
		return nil, fmt.Errorf("load account: %w", err)
	}

	salt, storedHash, err := parsePasswordHash(account.PasswordHash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parse password hash failed: %v\n", err)
		return nil, fmt.Errorf("parse hash: %w", err)
	}
	derivedHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	if !bytesEqual(derivedHash, storedHash) {
		return nil, fmt.Errorf("invalid password")
	}

	fixedSalt := make([]byte, 16)
	copy(fixedSalt, []byte(username+"zcomm_salt"))
	encryptionKey := argon2.IDKey([]byte(password), fixedSalt, 3, 64*1024, 4, 32)
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("invalid encryption key size: got %d, expected 32", len(encryptionKey))
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
			return nil, fmt.Errorf("create ZID: %w", err)
		}
		zid = identity.ID
		for _, existingZID := range account.ZIDs {
			if existingZID == zid {
				return nil, fmt.Errorf("generated ZID %s already exists in account", zid)
			}
		}
		account.ZIDs = append(account.ZIDs, zid)
		if err := saveAccount(account); err != nil {
			return nil, fmt.Errorf("save account: %w", err)
		}
		fmt.Printf("Created new ZID: %s\n", zid)
	} else if choice < 1 || choice > len(account.ZIDs) {
		return nil, fmt.Errorf("invalid ZID selection")
	} else {
		zid = account.ZIDs[choice-1]
	}

	storage, err := NewSQLiteStorage(zid)
	if err != nil {
		return nil, fmt.Errorf("initialize storage for ZID %s: %w", zid, err)
	}

	is, err := LoadIdentity(getIdentityPath(zid))
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	if is.identity == nil {
		return nil, fmt.Errorf("identity for %s not found", zid)
	}
	edPriv, ecdhPriv, err := DecryptIdentity(is.identity, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt identity: %w", err)
	}

	return NewApp(zid, edPriv, ecdhPriv, encryptionKey, storage), nil
}

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

func fetchNotifications(app *App) ([]core.Notification, int, error) {
	app.mu.RLock()
	ts, sig, err := createReqSignature(app.ZID, app.EdPriv)
	app.mu.RUnlock()
	if err != nil {
		return nil, 0, fmt.Errorf("create request signature: %w", err)
	}

	reqData := core.ReceiveRequest{ID: app.ZID, TS: ts, Sig: sig}
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

func fetchDispatches(app *App) ([]core.Dispatch, int, error) {
	app.mu.RLock()
	ts, sig, err := createReqSignature(app.ZID, app.EdPriv)
	app.mu.RUnlock()
	if err != nil {
		return nil, 0, fmt.Errorf("create request signature: %w", err)
	}

	reqData := core.ReceiveRequest{ID: app.ZID, TS: ts, Sig: sig}
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

func decryptLocalDispatch(disp *core.Dispatch, ecdhPriv [32]byte) (string, error) {
	localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

	var body string
	ciphertext, err := base64.StdEncoding.DecodeString(disp.Body)
	if err != nil {
		return "", fmt.Errorf("%s (failed to decode body: %v)", disp.Body, err)
	} else {
		nonce, err := base64.StdEncoding.DecodeString(disp.LocalNonce)
		if err != nil {
			return "", fmt.Errorf("%s (failed to decode local nonce: %v)", disp.Body, err)
		} else {
			plaintext, err := core.DecryptAESGCM(localKey[:], nonce, ciphertext)
			if err != nil {
				return "", fmt.Errorf("%s (local decryption failed: %v)", disp.Body, err)
			} else {
				body = string(plaintext)
			}
		}
	}

	return body, nil
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

func storeDispatchAndUpdateConversation(app *App, disp core.Dispatch) error {
	localKey := core.DeriveLocalEncryptionKey(app.ECDHPriv)
	fmt.Printf("pre-decryption: %s\n", disp.Body)
	plaintext := disp.Body
	if disp.Nonce != "" && disp.EphemeralPubKey != "" {
		if err := decryptDispatch(&disp, app.ECDHPriv); err != nil {
			return fmt.Errorf("decrypt received dispatch: %w", err)
		}
		plaintext = disp.Body
		fmt.Printf("decrypted?: %s\n", plaintext)
	}
	fmt.Printf("timestamp?: %v\n", disp.Timestamp)
	localCiphertext, localNonce, err := core.EncryptAESGCM(localKey[:], []byte(plaintext))
	if err != nil {
		return fmt.Errorf("encrypt for local storage: %w", err)
	}
	disp.Body = base64.StdEncoding.EncodeToString(localCiphertext)
	disp.LocalNonce = base64.StdEncoding.EncodeToString(localNonce)

	tx, err := app.Storage.(*SQLiteStorage).db.Beginx()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check if dispatch already exists
	var exists bool
	err = tx.Get(&exists, "SELECT EXISTS(SELECT 1 FROM Dispatches WHERE uuid = ?)", disp.UUID)
	if err != nil {
		return fmt.Errorf("check dispatch exists: %w", err)
	}
	if exists {
		return fmt.Errorf("dispatch %s already stored", disp.UUID)
	}

	// Check for matching dispatch in "awaiting" basket
	var awaitingDispatchID string
	err = tx.Get(&awaitingDispatchID, `
		SELECT b.dispatch_id
		FROM Baskets b
		JOIN Dispatches d ON b.dispatch_id = d.uuid
		WHERE d.to_zid = ? AND b.basket_name = 'awaiting' AND d.conversation_id = ?
		LIMIT 1
	`, disp.From, disp.ConversationID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("check awaiting basket: %w", err)
	}
	if awaitingDispatchID != "" {
		// Remove the matching dispatch from "awaiting"
		_, err = tx.Exec(`
			DELETE FROM Baskets
			WHERE basket_name = 'awaiting' AND dispatch_id = ?
		`, awaitingDispatchID)
		if err != nil {
			return fmt.Errorf("remove from awaiting basket: %w", err)
		}
		fmt.Printf("Removed dispatch %s from awaiting basket\n", awaitingDispatchID)
	}

	// Store dispatch (inlined from StoreDispatch)
	_, err = tx.Exec(`
		INSERT INTO Dispatches (uuid, from_zid, to_zid, subject, body, local_nonce, nonce, ephemeral_pub_key, conversation_id, signature, timestamp, is_end)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, disp.UUID, disp.From, disp.To, disp.Subject, disp.Body, disp.LocalNonce, disp.Nonce, disp.EphemeralPubKey, disp.ConversationID, disp.Signature, disp.Timestamp, disp.IsEnd)
	if err != nil {
		return fmt.Errorf("insert dispatch: %w", err)
	}

	// Get max sequence number
	var maxSeqNo sql.NullInt64
	err = tx.Get(&maxSeqNo, "SELECT MAX(seq_no) FROM ConversationDispatches WHERE con_id = ?", disp.ConversationID)
	if err != nil {
		return fmt.Errorf("get max seq_no for conversation %s: %w", disp.ConversationID, err)
	}
	seqNo := 1
	if maxSeqNo.Valid {
		seqNo = int(maxSeqNo.Int64) + 1
	}

	// Check if conversation exists
	var convExists bool
	err = tx.Get(&convExists, "SELECT EXISTS(SELECT 1 FROM Conversations WHERE con_id = ?)", disp.ConversationID)
	if err != nil {
		return fmt.Errorf("check conversation exists: %w", err)
	}

	// Store or update conversation (inlined from StoreConversation)
	if !convExists {
		_, err = tx.Exec(`
			INSERT INTO Conversations (con_id, subject, ended)
			VALUES (?, ?, ?)
		`, disp.ConversationID, disp.Subject, disp.IsEnd)
		if err != nil {
			return fmt.Errorf("insert conversation: %w", err)
		}
	} else {
		_, err = tx.Exec(`
			UPDATE Conversations
			SET ended = ?
			WHERE con_id = ?
		`, disp.IsEnd, disp.ConversationID)
		if err != nil {
			return fmt.Errorf("update conversation: %w", err)
		}
	}

	// Insert conversation dispatch
	_, err = tx.Exec(`
		INSERT INTO ConversationDispatches (con_id, dispatch_id, seq_no)
		VALUES (?, ?, ?)
	`, disp.ConversationID, disp.UUID, seqNo)
	if err != nil {
		return fmt.Errorf("insert conversation dispatch: %w", err)
	}

	var basket = "inbox"
	_, err = tx.Exec(`
		INSERT INTO Baskets (basket_name, dispatch_id, status)
		VALUES (?, ?, ?)
	`, basket, disp.UUID, "unread")
	if err != nil {
		return fmt.Errorf("insert basket %s: %w", basket, err)
	}

	return tx.Commit()
}

// func storeDispatchAndUpdateConversation(zid string, disp core.Dispatch, dispatches []core.Dispatch, storage Storage, ecdhPriv [32]byte) error {
// 	localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

// 	plaintext := disp.Body
// 	if disp.Nonce != "" && disp.EphemeralPubKey != "" {
// 		if err := decryptDispatch(&disp, ecdhPriv); err != nil {
// 			return fmt.Errorf("decrypt received dispatch: %w", err)
// 		}
// 		plaintext = disp.Body
// 	}

// 	localCiphertext, localNonce, err := core.EncryptAESGCM(localKey[:], []byte(plaintext))
// 	if err != nil {
// 		return fmt.Errorf("encrypt for local storage: %w", err)
// 	}
// 	disp.Body = base64.StdEncoding.EncodeToString(localCiphertext)
// 	disp.LocalNonce = base64.StdEncoding.EncodeToString(localNonce)

// 	if err := storage.StoreDispatch(zid, disp); err != nil {
// 		return fmt.Errorf("store dispatch: %w", err)
// 	}

// 	// Load the specific conversation
// 	conv, err := storage.LoadConversation(zid, disp.ConversationID)
// 	if err != nil {
// 		return fmt.Errorf("load conversation %s: %w", disp.ConversationID, err)
// 	}

// 	// Determine the next sequence number
// 	seqNo := 1
// 	for _, entry := range conv.Dispatches {
// 		if entry.SeqNo >= seqNo {
// 			seqNo = entry.SeqNo + 1
// 		}
// 	}

// 	// Store or update the conversation with the dispatch and Ended status
// 	if err := storage.StoreConversation(zid, disp.ConversationID, disp.UUID, seqNo, disp.Subject, disp.IsEnd); err != nil {
// 		return fmt.Errorf("store conversation: %w", err)
// 	}

// 	if err := storage.StoreBasket(zid, "inbox", disp.UUID); err != nil {
// 		return fmt.Errorf("store in inbox: %w", err)
// 	}

// 	//this logic sucks:
// 	//implement a dispatch linked list approach.
// 	unanswered, err := storage.LoadBasket(zid, "unanswered")
// 	if err != nil {
// 		return fmt.Errorf("load unanswered: %w", err)
// 	}
// 	for _, unansweredID := range unanswered {
// 		for _, unansweredDisp := range dispatches {
// 			if unansweredDisp.UUID == unansweredID && unansweredDisp.ConversationID == disp.ConversationID && unansweredDisp.To == disp.From {
// 				if err := storage.RemoveMessage(zid, "unanswered", unansweredID); err != nil {
// 					return fmt.Errorf("remove from unanswered: %w", err)
// 				}
// 				fmt.Printf("Removed dispatch %s from unanswered\n", unansweredID)
// 			}
// 		}
// 	}

// 	return nil
// }

// func checkForMessages(app *App) {
// 	backoff := 5 * time.Second
// 	maxBackoff := 60 * time.Second

// 	for {
// 		dispatches, statusCode, err := fetchDispatches(app)
// 		if err != nil {
// 			fmt.Fprintf(os.Stderr, "Fetch dispatches: %v\n", err)
// 			time.Sleep(backoff)
// 			backoff = min(maxBackoff, backoff*2)
// 			continue
// 		}

// 		if statusCode == http.StatusNoContent {
// 			backoff = 5 * time.Second
// 			time.Sleep(backoff)
// 			continue
// 		}

// 		if statusCode != http.StatusOK {
// 			fmt.Fprintf(os.Stderr, "Server error: status %d\n", statusCode)
// 			time.Sleep(backoff)
// 			continue
// 		}

// 		for _, disp := range dispatches {
// 			fmt.Printf("Received dispatch from %s at %d\n", disp.From, disp.Timestamp)
// 			keys, err := fetchPublicKeys(disp.From)
// 			if err != nil {
// 				fmt.Fprintf(os.Stderr, "Fetch sender keys for %s: %v\n", disp.From, err)
// 				continue
// 			}

// 			valid, err := verifyDispatch(disp, keys)
// 			if !valid || err != nil {
// 				fmt.Fprintf(os.Stderr, "Verification failed for dispatch from %s: %v\n", disp.From, err)
// 				continue
// 			}

// 			if err := storeDispatchAndUpdateConversation(app, disp); err != nil {
// 				fmt.Fprintf(os.Stderr, "Store dispatch from %s: %v\n", disp.From, err)
// 				continue
// 			}
// 			fmt.Println("Sending delivery notification")
// 			handleSendDelivery(app, disp)
// 		}

// 		backoff = 5 * time.Second
// 		time.Sleep(backoff)
// 	}
// }

// handleSendDelivery sends a delivery notification for a dispatch.
func handleSendDelivery(app *App, disp core.Dispatch) {
	is, err := LoadIdentity(getIdentityPath(app.ZID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load identity: %v\n", err)
		return
	}
	if is.identity == nil {
		fmt.Fprintf(os.Stderr, "Identity not initialized for %s\n", app.ZID)
		return
	}

	deliveryReceipt := &core.Notification{
		UUID:       uuid.New().String(),
		DispatchID: disp.UUID,
		From:       app.ZID,
		To:         disp.From,
		Type:       "delivery",
		Timestamp:  time.Now().Unix(),
	}

	app.mu.RLock()
	err = core.SignNotification(deliveryReceipt, app.EdPriv)
	app.mu.RUnlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign notification: %v\n", err)
		return
	}

	data, err := json.Marshal(deliveryReceipt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal delivery receipt: %v\n", err)
		return
	}

	resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
	if err != nil {
		if err := app.Storage.StorePendingNotification(*deliveryReceipt); err != nil {
			fmt.Fprintf(os.Stderr, "Store pending notification: %v\n", err)
		} else {
			fmt.Println("Stored delivery notification for later due to network error")
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read response body: %v\n", err)
	} else if resp.StatusCode != http.StatusOK {
		fmt.Printf("Server response body: %s\n", body)
	}

	if resp.StatusCode != http.StatusOK {
		if err := app.Storage.StorePendingNotification(*deliveryReceipt); err != nil {
			fmt.Fprintf(os.Stderr, "Store pending notification: %v\n", err)
		} else {
			fmt.Printf("Stored delivery notification for later: server returned %d\n", resp.StatusCode)
		}
		return
	}
	fmt.Println("Delivery notification sent successfully")
}

// handleSendRead sends a read notification for a dispatch.
func handleSendRead(app *App, disp core.Dispatch) {
	is, err := LoadIdentity(getIdentityPath(app.ZID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't load identity for read receipt: %v\n", err)
		return
	}
	if is.identity == nil {
		fmt.Fprintf(os.Stderr, "Identity not initialized for %s\n", app.ZID)
		return
	}

	readReceipt := &core.Notification{
		UUID:       uuid.New().String(),
		DispatchID: disp.UUID,
		From:       app.ZID,
		To:         disp.From,
		Type:       "read",
		Timestamp:  time.Now().Unix(),
	}

	app.mu.RLock()
	err = core.SignNotification(readReceipt, app.EdPriv)
	app.mu.RUnlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign read receipt: %v\n", err)
		return
	}

	if err := app.Storage.StoreReadReceipt(*readReceipt); err != nil {
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
		if err := app.Storage.StorePendingNotification(*readReceipt); err != nil {
			fmt.Fprintf(os.Stderr, "Queue read receipt: %v\n", err)
		} else {
			fmt.Printf("Read receipt queued due to %v\n", err)
		}
		if resp != nil {
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
func handleIncomingNotifications(app *App, notifs []core.Notification) {
	for _, notif := range notifs {
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

		valid, err := core.VerifyNotification(notif, pubKey)
		if !valid || err != nil {
			fmt.Fprintf(os.Stderr, "Invalid signature for notification %s from %s: %v\n", notif.UUID, notif.From, err)
			continue
		}

		thisDisp, err := app.Storage.GetDispatch(notif.DispatchID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Get dispatch %s for notification %s: %v\n", notif.DispatchID, notif.UUID, err)
			continue
		}

		switch notif.Type {
		case "delivery":
			err := app.Storage.MoveMessage("awaiting", "awaiting", notif.DispatchID, "Delivered")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Update delivered: %v\n", err)
			} else {
				fmt.Printf("Dispatch %s confirmed delivered\n", notif.DispatchID)
			}
		case "read":
			err = app.Storage.MoveMessage("awaiting", "awaiting", notif.DispatchID, "Read")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Update read: %v\n", err)
			} else {
				err = app.Storage.StoreReadReceipt(notif)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Store read receipt: %v\n", err)
				} else {
					fmt.Printf("Dispatch %s marked as read\n", notif.DispatchID)
				}
			}
		case "decline":
			err = app.Storage.StoreConversation(thisDisp.ConversationID, "", 0, thisDisp.Subject, true)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Archive conversation %s: %v\n", thisDisp.ConversationID, err)
				continue
			}

			basket := "awaiting"
			err = app.Storage.RemoveMessage(basket, thisDisp.UUID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Remove dispatch %s from %s: %v\n", thisDisp.UUID, basket, err)
			}

			fmt.Printf("Dispatch %s declined by %s, conversation %s archived\n", notif.DispatchID, notif.From, thisDisp.ConversationID)
		}
	}
}

func updateDeliveredDispatch(app *App, dispID string, disp core.Dispatch) error {
	if disp.IsEnd {
		if err := app.Storage.RemoveMessage("out", dispID); err != nil {
			return fmt.Errorf("remove from out: %w", err)
		}
	} else {
		if err := app.Storage.MoveMessage("unanswered", "unanswered", dispID, "delivered"); err != nil {
			return fmt.Errorf("move to unanswered: %w", err)
		}
	}
	fmt.Printf("Dispatch %s confirmed delivered\n", dispID)
	return nil
}

func pollNotifications(app *App) {
	backoff := 5 * time.Second
	maxBackoff := 60 * time.Second

	for {
		if !app.IsOnline() {
			// fmt.Println("Offline: Skipping notification fetch")
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		}
		if err := processPendingNotifications(app); err != nil {
			fmt.Fprintf(os.Stderr, "Process pending notifications: %v\n", err)
		}
		notifications, _, err := fetchNotifications(app)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fetch notifications: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		handleIncomingNotifications(app, notifications)
		time.Sleep(5 * time.Second)
	}
}

func createAndSendDispatch(app *App, recipient, subject, body, conversationID string, isEnd bool) error {
	is, err := LoadIdentity(filepath.Join("data", "identities", fmt.Sprintf("identity_%s.json", app.ZID)))
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	if is.identity == nil {
		return fmt.Errorf("identity for %s not found", app.ZID)
	}

	// Generate dispatch with fixed UUID
	app.mu.RLock()
	// disp, err := core.NewEncryptedDispatch(app.ZID, recipient, nil, nil, subject, body, conversationID, app.EdPriv, sharedKey, ephemeralPub, isEnd)
	disp, err := core.NewEncryptedDispatch(app.ZID, recipient, nil, nil, subject, body, conversationID, app.EdPriv, [32]byte{}, nil, isEnd)
	app.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("create dispatch: %w", err)
	}

	// Encrypt body for local storage
	localKey := core.DeriveLocalEncryptionKey(app.ECDHPriv)
	localCiphertext, localNonce, err := core.EncryptAESGCM(localKey[:], []byte(body))
	if err != nil {
		return fmt.Errorf("encrypt body for local storage: %w", err)
	}
	disp.Body = base64.StdEncoding.EncodeToString(localCiphertext)
	disp.LocalNonce = base64.StdEncoding.EncodeToString(localNonce)
	disp.Nonce = ""

	// Store dispatch once
	if err := app.Storage.StoreDispatch(*disp); err != nil {
		return fmt.Errorf("store dispatch: %w", err)
	}
	if err := app.Storage.StoreBasket("out", disp.UUID, ""); err != nil {
		return fmt.Errorf("store out: %w", err)
	}

	// Store conversation
	conv, err := app.Storage.LoadConversation(disp.ConversationID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("load conversation %s: %w", conversationID, err)
	}

	seqNo := 1
	for _, entry := range conv.Dispatches {
		if entry.SeqNo >= seqNo {
			seqNo = entry.SeqNo + 1
		}
	}

	if err := app.Storage.StoreConversation(disp.ConversationID, disp.UUID, seqNo, subject, isEnd); err != nil {
		return fmt.Errorf("store conversation: %w", err)
	}

	// Attempt to send if online
	// if app.IsOnline() {
	// 	disp.Body = body
	// 	err := EncryptAndSendDispatch(app, disp)
	// 	if err != nil {
	// 		fmt.Fprintf(os.Stderr, "Send dispatch failed, remains in out: %v\n", err)
	// 		return nil // Dispatch remains in OUT, no error
	// 	}
	// 	if err := app.Storage.MoveMessage("out", "awaiting", disp.UUID, "Sent"); err != nil {
	// 		return fmt.Errorf("move to awaiting: %w", err)
	// 	}
	// 	fmt.Printf("Dispatch %s sent successfully\n", disp.UUID)
	// } else {
	// 	fmt.Println("Offline: Dispatch queued in out basket")
	// }

	return nil
}

func handleAnswer(app *App, disp core.Dispatch, basket string, isEnd bool) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Reply body: ")
	body, _ := reader.ReadString('\n')
	body = strings.TrimSpace(body)

	if err := createAndSendDispatch(app, disp.From, disp.Subject, body, disp.ConversationID, isEnd); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return false
	}

	if err := app.Storage.RemoveMessage(basket, disp.UUID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove original: %v\n", err)
		return false
	}

	fmt.Printf("Reply sent to %s\n", disp.From)
	return true
}

func handlePending(app *App, basket, dispID string) bool {
	if basket != "pending" {
		if err := app.Storage.MoveMessage(basket, "pending", dispID, "read"); err != nil {
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
func handleACK(app *App, basket, dispID string, isEnd bool) bool {
	if !isEnd {
		fmt.Println("Only ACK dispatches can be removed with this option")
		return false
	}
	if err := app.Storage.RemoveMessage(basket, dispID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove ACK dispatch: %v\n", err)
		return false
	}
	fmt.Println("ACK dispatch removed")
	return true
}

func handleExit() bool {
	return false
}

func displayDispatch(app *App, disp core.Dispatch) {
	localKey := core.DeriveLocalEncryptionKey(app.ECDHPriv)

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
			err := decryptDispatch(&disp, app.ECDHPriv)
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
	if alias, err := app.Storage.ResolveAlias(disp.From); err == nil {
		sender = alias
	}

	fmt.Printf("To: %s From: %s\nSubject: %s", disp.To, sender, disp.Subject)
	if disp.IsEnd {
		fmt.Printf(" - ACK")
	}
	fmt.Printf("\nBody: %s\n", body)
}

func handleDispatchView(app *App, disp core.Dispatch, basket string) bool {
	displayDispatch(app, disp)
	if basket == "inbox" {
		handleSendRead(app, disp)
		processed := handlePending(app, "inbox", disp.UUID)
		if !processed {
			fmt.Println("Displayed but failed to process dispatch")
			return false
		}
		basket = "pending"
	}

	fmt.Println("1. Answer")
	if disp.IsEnd {
		fmt.Println("2. Delete ACK")
	} else {
		fmt.Println("2. ACK")
	}
	// fmt.Println("3. Decline to answer")
	fmt.Println("3. Exit")
	fmt.Print("Choose an option: ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		return handleAnswer(app, disp, basket, false)
	case "2":
		if disp.IsEnd {
			return handleACK(app, basket, disp.UUID, disp.IsEnd)
		}
		return handleAnswer(app, disp, basket, true)
	// case "3":
	// 	return handleDecline(app, disp, basket)
	case "3":
		return handleExit()
	default:
		fmt.Println("Invalid option")
		return false
	}
}

func handleSendDispatch(app *App) {
	reader := bufio.NewReader(os.Stdin)
	var found bool
	var recipient string
	for !found {
		fmt.Print("Enter recipient (alias/ZID or 0 to exit): ")
		fmt.Scanln(&recipient)

		resolved, err := app.Storage.ResolveAlias(recipient)
		if err != nil {
			if resolved == "0" {
				return
			}
			fmt.Printf("Failed to resolve alias: %s\n", err.Error())
			continue
		}
		recipient = resolved
		found = true
	}

	fmt.Print("Enter subject: ")
	subject, _ := reader.ReadString('\n')
	subject = strings.TrimSpace(subject)
	fmt.Print("Enter body: ")
	body, _ := reader.ReadString('\n')
	body = strings.TrimSpace(body)

	err := createAndSendDispatch(app, recipient, subject, body, "", false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Send dispatch: %v\n", err)
		return
	}
	fmt.Println("Dispatch sent")
}

// depreciate:
// func sendNewDispatch(zid string, edPriv ed25519.PrivateKey, encryptionKey []byte) error {
// 	reader := bufio.NewReader(os.Stdin)
// 	fmt.Print("To: ")
// 	to, _ := reader.ReadString('\n')
// 	to = strings.TrimSpace(to)
// 	fmt.Print("Subject: ")
// 	subject, _ := reader.ReadString('\n')
// 	subject = strings.TrimSpace(subject)
// 	fmt.Print("Body: ")
// 	body, _ := reader.ReadString('\n')
// 	body = strings.TrimSpace(body)

// 	if err := createAndSendDispatch(zid, to, subject, body, "", edPriv, encryptionKey, false, storage); err != nil {
// 		return err
// 	}
// 	fmt.Printf("Dispatch sent to %s\n", to)
// 	return nil
// }

func selectDispatchFromBasket(app *App, basket string) (core.Dispatch, bool) {
	disps, err := app.Storage.LoadBasketDispatches(basket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load basket: %v\n", err)
		return core.Dispatch{}, false
	}
	//basket is empty:
	if len(disps) < 1 {
		fmt.Printf("%s Basket is empty\n", basket)
		return core.Dispatch{}, false
	}
	displayBasketDispatches(app, disps, basket)

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
	disp, err := app.Storage.GetDispatch(disps[num-1].DispatchID)
	if err != nil {
		fmt.Printf("Failed to get dispatch: %v\n", err.Error())
		return core.Dispatch{}, false
	}

	return disp, true
}

func dateTimeFromUnix(t int64) string {
	unixTime := time.Unix(t, 0)
	return unixTime.Format("02/01/2006 15:04:05")
}

func displayBasketDispatches(app *App, disps []core.BasketDispatch, basket string) {
	for k, v := range disps {
		if basket == "awaiting" || basket == "out" {
			//if there is an error, ResolveAlias will simply give us the original input anyway so ignore the error in this case.
			alias, err := app.Storage.ResolveZID(v.To)
			if err != nil {
				fmt.Printf("error on resolve: %s\n", err.Error())
			}
			if alias != v.To {
				fmt.Printf("%d. %s To: %s (%s)\nSubject: %s", k+1, dateTimeFromUnix(v.Timestamp), alias, v.To, v.Subject)
			} else {
				fmt.Printf("%d. %s To: %s\nSubject: %s", k+1, dateTimeFromUnix(v.Timestamp), v.To, v.Subject)
			}
			if basket == "awaiting" && v.Status != "" {
				fmt.Printf(", Status: %s", v.Status)
			}
		} else {
			alias, err := app.Storage.ResolveZID(v.From)
			if err != nil {
				fmt.Printf("error on else resolve: %s\n", err.Error())
			}
			if alias != v.From {
				fmt.Printf("%d. %s From: %s (%s) \nSubject: %s", k+1, dateTimeFromUnix(v.Timestamp), alias, v.From, v.Subject)
			} else {
				fmt.Printf("%d. %s From: %s \nSubject: %s", k+1, dateTimeFromUnix(v.Timestamp), v.From, v.Subject)
			}

		}
		if v.IsEnd {
			fmt.Printf(" - ACK")
		}
		fmt.Println()
	}
}

func viewBasket(app *App, basket string) {
	disps, err := app.Storage.LoadBasketDispatches(basket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load basket: %v\n", err)
		return
	}
	if len(disps) == 0 {
		fmt.Println("No dispatches found")
		return
	}
	switch strings.ToLower(basket) {
	case "inbox", "pending":
		for {
			disp, ok := selectDispatchFromBasket(app, basket)
			if !ok {
				return
			}
			if !handleDispatchView(app, disp, basket) {
				return
			}
		}
	case "out":
		disp, ok := selectDispatchFromBasket(app, basket)
		if !ok {
			return
		}
		displayDispatch(app, disp)
		app.Storage.HandleOutBasketDispatch(disp)
	case "awaiting":
		displayBasketDispatches(app, disps, basket)
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
			if err := app.Storage.RemoveMessage("awaiting", disp.DispatchID); err != nil {
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

		selected, err := app.Storage.GetDispatch(disps[num-1].DispatchID)
		if err != nil {
			fmt.Println("Couldn't find dispatch")
		}

		displayDispatch(app, selected)
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

	var app *App
	var err error

	if choice == "1" {
		app, err = promptLogin()
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
		app, err = promptLogin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Invalid option\n")
		os.Exit(1)
	}

	defer app.Logout()

	go sendAndReceive(app)
	go pollNotifications(app)

	reader = bufio.NewReader(os.Stdin)
	for {
		inIds, pendingIds, outIds, awaitingIds, err := LoadBasketCounts(app)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load baskets: %v\n", err)
		}

		fmt.Printf("ZID: %s:", app.ZID)
		if app.isOnlineCached {
			fmt.Printf("Online\n")
		} else {
			fmt.Printf("Offline\n")
		}

		fmt.Printf("\n1. Send Dispatch\n")
		fmt.Printf("2. View Inbox [%v]\n", inIds)
		fmt.Printf("3. View Pending [%v]\n", pendingIds)
		fmt.Printf("4. View Out [%v]\n", outIds)
		fmt.Printf("5. View Awaiting [%v]\n", awaitingIds)
		fmt.Printf("6. View Conversations\n")
		fmt.Printf("7. View Archived Conversations\n")
		fmt.Printf("8. Manage Contacts\n")
		fmt.Printf("9. Exit\n")
		fmt.Print("Choose an option: ")

		choice, _ = reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			handleSendDispatch(app)
		case "2":
			viewBasket(app, "inbox")
		case "3":
			viewBasket(app, "pending")
		case "4":
			viewBasket(app, "out")
		case "5":
			viewBasket(app, "awaiting")
		case "6":
			app.Storage.ViewConversations(app, false)
		case "7":
			app.Storage.ViewConversations(app, true)
		case "8":
			handleContacts(app.Storage)
		case "9":
			os.Exit(0)
		default:
			fmt.Println("Invalid option")
		}
	}
}

func processPendingNotifications(app *App) error {
	notifs, err := app.Storage.LoadPendingNotifications()
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
		if err := app.Storage.RemovePendingNotification(notif.UUID, notif.Type); err != nil {
			fmt.Fprintf(os.Stderr, "Remove pending notification %s: %v\n", notif.UUID, err)
			continue
		}
		fmt.Printf("Sent queued %s notification %s\n", notif.Type, notif.UUID)
	}
	return nil
}

func LoadBasketCounts(app *App) (int, int, int, int, error) {
	inIds, err := app.Storage.LoadBasket("inbox")
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("load in: %v", err)
	}
	pendingIds, err := app.Storage.LoadBasket("pending")
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("load pending: %v", err)
	}
	outIds, err := app.Storage.LoadBasket("out")
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("load out: %v", err)
	}
	awaitingIds, err := app.Storage.LoadBasket("awaiting")
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("load awaiting: %v", err)
	}

	return len(inIds), len(pendingIds), len(outIds), len(awaitingIds), nil
}

func LoadBaskets(app *App) ([]string, []string, []string, []string, error) {
	inIds, err := app.Storage.LoadBasket("inbox")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load in: %v", err)
	}
	pendingIds, err := app.Storage.LoadBasket("pending")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load pending: %v", err)
	}
	outIds, err := app.Storage.LoadBasket("out")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load out: %v", err)
	}
	unansweredIds, err := app.Storage.LoadBasket("unanswered")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load unanswered: %v", err)
	}

	return inIds, pendingIds, outIds, unansweredIds, nil
}

func handleContacts(storage Storage) {
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

			keys, err := fetchPublicKeys(contactZID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Fetch public keys: %v\n", err)
				continue
			}

			err = storage.AddContact(alias, contactZID, keys.EdPub, keys.ECDHPub)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Add contact: %v\n", err)
				continue
			}
			fmt.Printf("Contact %s added with ZID %s\n", alias, contactZID)

		case "2":
			contacts, err := storage.ListContacts()
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
			err := storage.RemoveContact(alias)
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

func handleDecline(app *App, disp core.Dispatch, basket string) bool {
	notif := core.Notification{
		UUID:       uuid.New().String(),
		DispatchID: disp.UUID,
		From:       app.ZID,
		To:         disp.From,
		Type:       "decline",
		Timestamp:  time.Now().Unix(),
	}

	if err := app.Storage.RemoveMessage(basket, disp.UUID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove dispatch: %v\n", err)
		return false
	}

	app.mu.RLock()
	if err := core.SignNotification(&notif, app.EdPriv); err != nil {
		fmt.Fprintf(os.Stderr, "Sign decline notification: %v\n", err)
		app.mu.RUnlock()
		return false
	}
	app.mu.RUnlock()

	data, err := json.Marshal(notif)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal delivery receipt: %v\n", err)
		return false
	}

	resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
	if err != nil {
		if err := app.Storage.StorePendingNotification(notif); err != nil {
			fmt.Fprintf(os.Stderr, "Store pending notification: %v\n", err)
		} else {
			fmt.Println("Stored delivery notification for later due to network error")
		}
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read response body: %v\n", err)
	} else if resp.StatusCode != http.StatusOK {
		fmt.Printf("Server response body: %s\n", body)
	}

	if resp.StatusCode != http.StatusOK {
		if err := app.Storage.StorePendingNotification(notif); err != nil {
			fmt.Fprintf(os.Stderr, "Store pending decline notification: %v\n", err)
		} else {
			fmt.Printf("Stored decline notification for later: server returned %d\n", resp.StatusCode)
		}
		return false
	}
	fmt.Println("Delivery notification sent successfully")

	if err := app.Storage.StoreConversation(disp.ConversationID, "", 0, disp.Subject, true); err != nil {
		fmt.Fprintf(os.Stderr, "Archive conversation: %v\n", err)
		return false
	}

	fmt.Println("Dispatch declined and conversation archived")
	return true
}

// checkForMessages fetches incoming dispatches and sends queued dispatches from the "out" basket.
func sendAndReceive(app *App) {
	backoff := 5 * time.Second
	maxBackoff := 60 * time.Second

	for {
		// Check if online before fetching or sending
		if !app.IsOnline() {
			// fmt.Println("Offline: Skipping fetch and send operations")
			time.Sleep(backoff)
			continue
		}

		dispatches, statusCode, err := fetchDispatches(app)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fetch dispatches: %v\n", err)
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		}

		if statusCode == http.StatusNoContent {
			// No new dispatches
			backoff = 5 * time.Second
		} else if statusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "Server error: status %d\n", statusCode)
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		} else {
			// Process incoming dispatches
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

				if err := storeDispatchAndUpdateConversation(app, disp); err != nil {
					fmt.Fprintf(os.Stderr, "Store dispatch from %s: %v\n", disp.From, err)
					continue
				}
				fmt.Println("Sending delivery notification")
				handleSendDelivery(app, disp)
			}
			backoff = 5 * time.Second
		}

		// Send queued dispatches from OUT
		outDispatches, err := app.Storage.LoadBasketDispatches("out")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load out basket: %v\n", err)
			time.Sleep(backoff)
			continue
		}

		for _, basketDisp := range outDispatches {
			disp, err := app.Storage.GetDispatch(basketDisp.DispatchID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Load dispatch %s: %v\n", basketDisp.DispatchID, err)
				continue
			}
			fmt.Printf("Got dispatch for sending with time: %s\n", dateTimeFromUnix(disp.Timestamp))
			// Decrypt body for sending
			disp.Body, err = decryptLocalDispatch(&disp, app.ECDHPriv)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Decrypt dispatch %s: %v\n", disp.UUID, err)
				if err := app.Storage.MoveMessage("out", "failed", disp.UUID, ""); err != nil {
					fmt.Fprintf(os.Stderr, "Move to failed: %v\n", err)
				}
				continue
			}

			fmt.Printf("Decrypted before being sent: %s\n", disp.Body)
			fmt.Printf("Time before being sent: %s\n", dateTimeFromUnix(disp.Timestamp))
			// Send using stored details
			err = EncryptAndSendDispatch(app, &disp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Send dispatch %s to %s: %v\n", disp.UUID, disp.To, err)
				if err := app.Storage.MoveMessage("out", "failed", disp.UUID, ""); err != nil {
					fmt.Fprintf(os.Stderr, "Move to failed: %v\n", err)
				}
				continue
			}

			// Update dispatch fields
			if err := app.Storage.UpdateDispatchFields(disp.UUID, disp.Nonce, disp.EphemeralPubKey, disp.Signature); err != nil {
				fmt.Fprintf(os.Stderr, "Update dispatch fields %s: %v\n", disp.UUID, err)
				continue
			}

			//if this is an ack, remove from out, else we expect an answer.
			if disp.IsEnd {
				err = app.Storage.RemoveMessage("out", disp.UUID)
				if err != nil {
					fmt.Printf("Failed to remove from out: %s\n", err.Error())
				}
			} else {
				if err := app.Storage.MoveMessage("out", "awaiting", disp.UUID, "sent"); err != nil {
					fmt.Fprintf(os.Stderr, "Move to awaiting: %v\n", err)
					continue
				}
			}
			// Move to awaiting

			fmt.Printf("Dispatch %s sent successfully\n", disp.UUID)
		}

		time.Sleep(backoff)
	}
}

// EncryptAndSendDispatch takes a cleartext body dispatch, encrypts it for the recipient and sends it.
// It populates disp.Nonce, disp.EphemeralPubKey, disp.Signature
func EncryptAndSendDispatch(app *App, disp *core.Dispatch) error {
	keys, err := fetchPublicKeys(disp.To)
	if err != nil {
		return fmt.Errorf("fetch recipient keys: %w", err)
	}

	ecdhPub, err := base64.StdEncoding.DecodeString(keys.ECDHPub)
	if err != nil {
		return fmt.Errorf("decode ECDH key: %w", err)
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
	disp.EphemeralPubKey = base64.StdEncoding.EncodeToString(ephemeralPub)

	shared, err := curve25519.X25519(ephemeralPriv[:], ecdhPubKey[:])
	if err != nil {
		return fmt.Errorf("derive shared key: %w", err)
	}
	var sharedKey [32]byte
	copy(sharedKey[:], shared)

	// Use EncryptAESGCM for transmission encryption
	ciphertext, nonce, err := core.EncryptAESGCM(sharedKey[:], []byte(disp.Body))
	if err != nil {
		return fmt.Errorf("encrypt dispatch: %w", err)
	}
	disp.Nonce = base64.StdEncoding.EncodeToString(nonce)
	disp.Body = base64.StdEncoding.EncodeToString(ciphertext)

	// Sign the dispatch
	if err := core.SignDispatch(disp, app.EdPriv); err != nil {
		return fmt.Errorf("sign dispatch: %w", err)
	}

	fmt.Printf("Sending with time stamp: %s", dateTimeFromUnix(disp.Timestamp))
	// Send the dispatch
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

	// Update dispatch fields in storage
	if err := app.Storage.UpdateDispatchFields(disp.UUID, disp.Nonce, disp.EphemeralPubKey, disp.Signature); err != nil {
		return fmt.Errorf("update dispatch fields: %w", err)
	}

	return nil
}
