// cmd/client/main.go
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jadefox10200/zcomm/core"
	"golang.org/x/crypto/curve25519"
)

const serverURL = "http://localhost:8080"

// storage is the global Storage interface for database access
var storage Storage

// fetchPublicKeys retrieves public keys for a given ZID from the server.
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

// fetchNotifications sends a POST request to retrieve notifications from the server.
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

// fetchDispatches sends a POST request to retrieve dispatches from the server.
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

// decryptDispatch decrypts the body of a dispatch using the shared key.
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

// clearConversationDispatches removes related dispatches for an ACK, keeping the ACK itself.
// func clearConversationDispatches(zid, conversationID, excludeUUID string, dispatches []core.Dispatch) error {
// 	for _, basket := range []string{"inbox", "unanswered"} {
// 		dispIDs, err := storage.LoadBasket(zid, basket)
// 		if err != nil {
// 			return fmt.Errorf("load %s: %w", basket, err)
// 		}
// 		for _, dispID := range dispIDs {
// 			for _, d := range dispatches {
// 				if d.UUID == dispID && d.ConversationID == conversationID && d.UUID != excludeUUID {
// 					if err := storage.RemoveMessage(zid, basket, dispID); err != nil {
// 						return fmt.Errorf("remove from %s: %w", basket, err)
// 					}
// 				}
// 			}
// 		}
// 	}
// 	return nil
// }

// storeDispatchAndUpdateConversation stores a dispatch and updates conversation state.
func storeDispatchAndUpdateConversation(zid string, disp core.Dispatch, dispatches []core.Dispatch, storage Storage, ecdhPriv [32]byte) error {

	// Get local encryption key
	localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

	// Decrypt received dispatch if encrypted
	plaintext := disp.Body
	if disp.Nonce != "" && disp.EphemeralPubKey != "" {
		if err := decryptDispatch(&disp, ecdhPriv); err != nil {
			return fmt.Errorf("decrypt received dispatch: %w", err)
		}
		plaintext = disp.Body
	}

	// Encrypt for local storage
	localCiphertext, localNonce, err := core.EncryptAESGCM(localKey[:], []byte(plaintext))
	if err != nil {
		return fmt.Errorf("encrypt body for local storage: %w", err)
	}

	// Update dispatch with locally encrypted body and nonce
	disp.Body = base64.StdEncoding.EncodeToString(localCiphertext)
	disp.LocalNonce = base64.StdEncoding.EncodeToString(localNonce)

	// Store dispatch
	if err := storage.StoreDispatch(zid, disp); err != nil {
		return fmt.Errorf("store dispatch: %w", err)
	}
	//==

	// Rest of the function remains unchanged
	if disp.IsEnd {
		convs, err := storage.LoadConversations(zid)
		if err != nil {
			return fmt.Errorf("load conversations: %w", err)
		}
		for i, conv := range convs {
			if conv.ConID == disp.ConversationID {
				convs[i].Ended = true
				if err := storage.StoreConversation(zid, conv.ConID, "", 0, conv.Subject); err != nil {
					return fmt.Errorf("update conversation: %w", err)
				}
				break
			}
		}
		if err := storage.EndConversation(zid, disp.ConversationID, disp.IsEnd); err != nil {
			return fmt.Errorf("archive conversation: %w", err)
		}
		fmt.Printf("Conversation %s ended by %s\n", disp.ConversationID, disp.From)
	}

	if err := storage.StoreBasket(zid, "inbox", disp.UUID); err != nil {
		return fmt.Errorf("store inbox: %w", err)
	}

	convs, err := storage.LoadConversations(zid)
	if err != nil {
		return fmt.Errorf("load conversations: %w", err)
	}
	seqNo := 1
	for _, conv := range convs {
		if conv.ConID == disp.ConversationID {
			for _, entry := range conv.Dispatches {
				if entry.SeqNo >= seqNo {
					seqNo = entry.SeqNo + 1
				}
			}
		}
	}
	if err := storage.StoreConversation(zid, disp.ConversationID, disp.UUID, seqNo, disp.Subject); err != nil {
		return fmt.Errorf("store conversation: %w", err)
	}

	unanswered, err := storage.LoadBasket(zid, "unanswered")
	if err != nil {
		return fmt.Errorf("load unanswered: %w", err)
	}
	for _, unansweredID := range unanswered {
		for _, unansweredDisp := range dispatches {
			if unansweredDisp.UUID == unansweredID && unansweredDisp.ConversationID == disp.ConversationID && unansweredDisp.To[0] == disp.From {
				if err := storage.RemoveMessage(zid, "unanswered", unansweredID); err != nil {
					return fmt.Errorf("remove unanswered: %w", err)
				}
				fmt.Printf("Removed dispatch %s from unanswered\n", unansweredID)
			}
		}
	}
	return nil
}

// --
func checkForMessages(zid string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) {
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

			// Store dispatch with local encryption
			if err := storeDispatchAndUpdateConversation(zid, disp, localDispatches, storage, ecdhPriv); err != nil {
				fmt.Fprintf(os.Stderr, "Store dispatch from %s: %v\n", disp.From, err)
				continue
			}
			handleSendDelivery(disp, zid)
		}

		backoff = 5 * time.Second
		time.Sleep(backoff)
	}
}

//--

// checkForMessages polls the server for new dispatches and processes them.
// func checkForMessages(zid string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) {
// 	backoff := 5 * time.Second
// 	maxBackoff := 60 * time.Second

// 	for {
// 		// Send any pending notifications
// 		if err := processPendingNotifications(zid); err != nil {
// 			fmt.Fprintf(os.Stderr, "Process pending notifications: %v\n", err)
// 		}

// 		// Create signature to make receive request
// 		ts, sig, err := createReqSignature(zid, edPriv)
// 		if err != nil {
// 			fmt.Fprintf(os.Stderr, "%v\n", err)
// 			time.Sleep(backoff)
// 			continue
// 		}

// 		// Request dispatches from the server
// 		dispatches, statusCode, err := fetchDispatches(zid, ts, sig)
// 		if err != nil {
// 			fmt.Fprintf(os.Stderr, "%v\n", err)
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

// 		localDispatches, err := storage.LoadDispatches(zid)
// 		if err != nil {
// 			fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
// 			continue
// 		}

// 		for _, disp := range dispatches {
// 			fmt.Printf("Received dispatch from %s at %d\n", disp.From, disp.Timestamp)
// 			keys, err := fetchPublicKeys(disp.From)
// 			if err != nil {
// 				fmt.Fprintf(os.Stderr, "Fetch sender keys: %v\n", err)
// 				continue
// 			}

// 			if valid, err := verifyDispatch(disp, keys); !valid || err != nil {
// 				fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
// 				continue
// 			}

// 			//DO NOT DECRYPT BEFORE STORING THE DISPATCH.
// 			// if err := decryptDispatch(&disp, ecdhPriv); err != nil {
// 			// 	fmt.Fprintf(os.Stderr, "%v\n", err)
// 			// 	continue
// 			// }

// 			if err := storeDispatchAndUpdateConversation(zid, disp, localDispatches, storage); err != nil {
// 				fmt.Fprintf(os.Stderr, "%v\n", err)
// 				continue
// 			}
// 			handleSendDelivery(disp, zid, edPriv)
// 		}

// 		backoff = 5 * time.Second
// 		time.Sleep(backoff)
// 	}
// }

func handleSendDelivery(disp core.Dispatch, zid string) {
	identity, err := LoadIdentity(getIdentityPath(zid))
	if err != nil {
		return
	}
	if identity.identity == nil {
		return
	}
	deliveryReceipt := core.Notification{
		UUID:       uuid.New().String(),
		DispatchID: disp.UUID,
		From:       zid,
		To:         disp.From,
		Type:       "delivery",
		Timestamp:  time.Now().Unix(),
		PubKey:     identity.identity.EdPub,
	}
	deliveryReceipt.Signature, err = signNotification(identity.identity, deliveryReceipt)
	if err != nil {
		return
	}
	data, err := json.Marshal(deliveryReceipt)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
	if err != nil {
		storage.StorePendingNotification(zid, deliveryReceipt)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		storage.StorePendingNotification(zid, deliveryReceipt)
		return
	}
}

// updateDeliveredDispatch updates the basket for a confirmed dispatch.
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

func handleIncomingNotifications(zid string, notifs []core.Notification, disps []core.Dispatch) {
	for _, notif := range notifs {
		// Verify notification signature for security
		pubKey, err := base64.StdEncoding.DecodeString(notif.PubKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			continue
		}

		if !verifyNotification(notif, pubKey) {
			fmt.Fprintf(os.Stderr, "Invalid signature for notification %s from %s\n", notif.UUID, notif.From)
			continue
		}

		var thisDisp core.Dispatch
		for _, disp := range disps {
			if disp.UUID == notif.DispatchID {
				thisDisp = disp
				break
			}
		}
		switch notif.Type {
		case "delivery":
			err := updateDeliveredDispatch(zid, notif.DispatchID, thisDisp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "update delivered: %v\n", err)
			}
		case "read":
			err = storage.StoreReadReceipt(zid, notif)
			if err != nil {
				fmt.Fprintf(os.Stderr, "incoming store read receipt: %v\n", err)
			}
		}
	}
}

func pollNotifications(zid string, edPriv ed25519.PrivateKey) {
	for {
		// Create signature to make receive request
		ts, sig, err := createReqSignature(zid, edPriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Request notifications from the server
		notifications, _, err := fetchNotifications(zid, ts, sig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		localDispatches, err := storage.LoadDispatches(zid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load dispatches: %v\n", err)
			continue
		}

		handleIncomingNotifications(zid, notifications, localDispatches)
		time.Sleep(5 * time.Second)
	}
}

// createAndSendDispatch creates and sends a new dispatch (reply or regular).
func createAndSendDispatch(zid, recipient, subject, body, conversationID string, edPriv ed25519.PrivateKey, isEnd bool, storage Storage) error {
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

	// Create dispatch with transmission encryption
	disp, err := core.NewEncryptedDispatch(zid, []string{recipient}, nil, nil, subject, body, conversationID, edPriv, sharedKey, ephemeralPub)
	if err != nil {
		return fmt.Errorf("create dispatch: %w", err)
	}
	disp.IsEnd = isEnd

	// Create a copy for local storage
	localDisp := *disp

	// Get local encryption key
	ecdhPrivBytes, err := base64.StdEncoding.DecodeString(identity.ECDHPriv)
	if err != nil {
		return fmt.Errorf("decode ecdh private key: %w", err)
	}
	var ecdhPriv [32]byte
	copy(ecdhPriv[:], ecdhPrivBytes)
	localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

	// Encrypt body for local storage using the original plaintext
	localCiphertext, localNonce, err := core.EncryptAESGCM(localKey[:], []byte(body))
	if err != nil {
		return fmt.Errorf("encrypt body for local storage: %w", err)
	}

	// Update local dispatch with locally encrypted body and nonce
	localDisp.Body = base64.StdEncoding.EncodeToString(localCiphertext)
	localDisp.LocalNonce = base64.StdEncoding.EncodeToString(localNonce)

	// Store local dispatch
	if err := storage.StoreDispatch(zid, localDisp); err != nil {
		return fmt.Errorf("store dispatch: %w", err)
	}
	if err := storage.StoreBasket(zid, "out", localDisp.UUID); err != nil {
		return fmt.Errorf("store out: %w", err)
	}

	// Update conversation
	convs, err := storage.LoadConversations(zid)
	if err != nil {
		return fmt.Errorf("load conversations: %w", err)
	}
	seqNo := 1
	for _, conv := range convs {
		if conv.ConID == disp.ConversationID {
			for _, entry := range conv.Dispatches {
				if entry.SeqNo >= seqNo {
					seqNo = entry.SeqNo + 1
				}
			}
		}
	}
	if err := storage.StoreConversation(zid, disp.ConversationID, disp.UUID, seqNo, disp.Subject); err != nil {
		return fmt.Errorf("store conversation: %w", err)
	}

	if isEnd {
		for i, conv := range convs {
			if conv.ConID == disp.ConversationID {
				convs[i].Ended = true
				if err := storage.StoreConversation(zid, conv.ConID, "", 0, conv.Subject); err != nil {
					return fmt.Errorf("update conversation: %w", err)
				}
				break
			}
		}
		if err := storage.EndConversation(zid, disp.ConversationID, isEnd); err != nil {
			return fmt.Errorf("archive conversation: %w", err)
		}
	}

	// Send the original transmission-encrypted dispatch
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

// handleAnswer processes the "Answer" option for a dispatch.
func handleAnswer(zid string, disp core.Dispatch, basket string, edPriv ed25519.PrivateKey, isEnd bool) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Reply body: ")
	body, _ := reader.ReadString('\n')
	body = strings.TrimSpace(body)

	if err := createAndSendDispatch(zid, disp.From, disp.Subject, body, disp.ConversationID, edPriv, isEnd, storage); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return false
	}

	if err := storage.RemoveMessage(zid, basket, disp.UUID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove original: %v\n", err)
		return false
	}

	fmt.Printf("Reply sent to %s\n", disp.From)
	return true
}

// handlePending moves a dispatch to the pending basket.
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

// handleACK removes an ACK dispatch from the basket.
func handleACK(zid, basket, dispID, dispConvID string, isEnd bool) bool {
	if !isEnd {
		fmt.Println("Only ACK dispatches can be removed with this option")
		return false
	}
	fmt.Printf("Try to remove: zid:%s\nbasket:%s\ndisp:%s\n", zid, basket, dispID)
	if err := storage.RemoveMessage(zid, basket, dispID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove ACK dispatch: %v\n", err)
		return false
	}
	if err := storage.EndConversation(zid, dispConvID, isEnd); err != nil {
		fmt.Fprintf(os.Stderr, "Archive conversation: %v\n", err)
		return false
	}
	fmt.Println("ACK dispatch removed")
	return true
}

// handleExit exits the dispatch view without action.
func handleExit() bool {
	return false
}

func displayDispatch(zid string, disp core.Dispatch, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) {
	// Get local key
	localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

	// Decrypt body
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
		// Legacy handling
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

	// Display the dispatch
	fmt.Printf("To: %s From: %s\nSubject: %s", disp.To, disp.From, disp.Subject)
	if disp.IsEnd {
		fmt.Printf(" - ACK")
	}
	fmt.Printf("\nBody: %s\n", body)
}

// handleDispatchView displays a dispatch and prompts for actions.
func handleDispatchView(zid string, disp core.Dispatch, basket string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) bool {
	// Get local key
	// localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

	// // Decrypt body
	// var body string
	// if disp.LocalNonce != "" {
	// 	ciphertext, err := base64.StdEncoding.DecodeString(disp.Body)
	// 	if err != nil {
	// 		body = fmt.Sprintf("%s (failed to decode body: %v)", disp.Body, err)
	// 	} else {
	// 		nonce, err := base64.StdEncoding.DecodeString(disp.LocalNonce)
	// 		if err != nil {
	// 			body = fmt.Sprintf("%s (failed to decode local nonce: %v)", disp.Body, err)
	// 		} else {
	// 			plaintext, err := core.DecryptAESGCM(localKey[:], nonce, ciphertext)
	// 			if err != nil {
	// 				body = fmt.Sprintf("%s (local decryption failed: %v)", disp.Body, err)
	// 			} else {
	// 				body = string(plaintext)
	// 			}
	// 		}
	// 	}
	// } else {
	// 	// Legacy handling
	// 	if disp.Nonce != "" && disp.EphemeralPubKey != "" {
	// 		err := decryptDispatch(&disp, ecdhPriv)
	// 		if err != nil {
	// 			body = fmt.Sprintf("%s (transmission decryption failed: %v)", disp.Body, err)
	// 		} else {
	// 			body = disp.Body
	// 		}
	// 	} else {
	// 		body = disp.Body
	// 	}
	// }

	// // Display the dispatch
	// fmt.Printf("To: %s From: %s\nSubject: %s", disp.To, disp.From, disp.Subject)
	// if disp.IsEnd {
	// 	fmt.Printf(" - ACK")
	// }
	// fmt.Printf("\nBody: %s\n", body)

	// Rest of the function unchanged

	displayDispatch(zid, disp, edPriv, ecdhPriv)
	handleSendRead(disp, zid)
	fmt.Println("1. Answer")
	if disp.IsEnd {
		fmt.Println("2. Delete ACK")
		fmt.Println("3. Exit")
	} else {
		fmt.Println("2. Place in Pending")
		fmt.Println("3. End Conversation")
		fmt.Println("4. Exit")
	}
	fmt.Print("Choose an option: ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		return handleAnswer(zid, disp, basket, edPriv, false)
	case "2":
		if disp.IsEnd {
			return handleACK(zid, basket, disp.UUID, disp.ConversationID, disp.IsEnd)
		}
		return handlePending(zid, basket, disp.UUID)
	case "3":
		if disp.IsEnd {
			return handleExit()
		}
		return handleAnswer(zid, disp, basket, edPriv, true)
	case "4":
		if disp.IsEnd {
			fmt.Println("Invalid option")
		}
		return false
	default:
		fmt.Println("Invalid option")
		return false
	}
}

// sendNewDispatch creates and sends a new dispatch from user input.
func sendNewDispatch(zid string, edPriv ed25519.PrivateKey) error {
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

	if err := createAndSendDispatch(zid, to, subject, body, "", edPriv, false, storage); err != nil {
		return err
	}
	fmt.Printf("Dispatch sent to %s\n", to)
	return nil
}

// selectDispatchFromBasket displays dispatches in a basket and returns the selected one.
func selectDispatchFromBasket(zid, basket string) (core.Dispatch, bool) {
	dispIDs, err := storage.LoadBasket(zid, basket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load %s: %v\n", basket, err)
		return core.Dispatch{}, false
	}
	if len(dispIDs) == 0 {
		fmt.Printf("%s is empty\n", strings.Title(basket))
		return core.Dispatch{}, false
	}

	dispatches, err := storage.LoadDispatches(zid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
		return core.Dispatch{}, false
	}

	for i, dispID := range dispIDs {
		for _, disp := range dispatches {
			if disp.UUID == dispID {
				if basket == "unanswered" {
					fmt.Printf("%d. To: %s, Subject: %s\n", i+1, disp.To[0], disp.Subject)
				} else {
					fmt.Printf("%d. From: %s, Subject: %s", i+1, disp.From, disp.Subject)
					if disp.IsEnd {
						fmt.Printf(" - ACK")
					}
					fmt.Printf("\n")
				}
			}
		}
	}

	fmt.Print("Select dispatch number (0 to exit): ")
	var num int
	fmt.Scanln(&num)
	if num == 0 {
		return core.Dispatch{}, false
	}
	if num < 1 || num > len(dispIDs) {
		fmt.Println("Invalid selection")
		return core.Dispatch{}, false
	}

	for _, disp := range dispatches {
		if disp.UUID == dispIDs[num-1] {
			return disp, true
		}
	}
	return core.Dispatch{}, false
}

// viewBasket displays and processes dispatches in a specified basket.
func viewBasket(zid, basket string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) {
	if basket == "unanswered" {
		dispIDs, err := storage.LoadBasket(zid, basket)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load unanswered: %v\n", err)
			return
		}
		if len(dispIDs) == 0 {
			fmt.Println("No unanswered dispatches")
			return
		}

		dispatches, err := storage.LoadDispatches(zid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
			return
		}

		for i, dispID := range dispIDs {
			for _, disp := range dispatches {
				if disp.UUID == dispID {
					fmt.Printf("%d. To: %s, Subject: %s\n", i+1, disp.To[0], disp.Subject)
				}
			}
		}

		fmt.Print("Select dispatch number (0 to exit, -N to forget): ")
		var num int
		fmt.Scanln(&num)
		if num == 0 {
			return
		}
		if num < 0 {
			num = -num
			if num < 1 || num > len(dispIDs) {
				fmt.Println("Invalid selection")
				return
			}
			dispID := dispIDs[num-1]
			if err := storage.RemoveMessage(zid, "unanswered", dispID); err != nil {
				fmt.Fprintf(os.Stderr, "Forget dispatch: %v\n", err)
				return
			}
			fmt.Printf("Dispatch %s forgotten\n", dispID)
			return
		}
		if num < 1 || num > len(dispIDs) {
			fmt.Println("Invalid selection")
			return
		}

		var selected core.Dispatch
		for _, disp := range dispatches {
			if disp.UUID == dispIDs[num-1] {
				selected = disp
				break
			}
		}

		displayDispatch(zid, selected, edPriv, ecdhPriv)
		// fmt.Printf("To: %s\nSubject: %s\nBody: %s\n", selected.To[0], selected.Subject, selected.Body)
		// fmt.Print("Press Enter to continue...")
		// reader := bufio.NewReader(os.Stdin)
		// reader.ReadString('\n')
		return
	}

	disp, ok := selectDispatchFromBasket(zid, basket)
	if !ok {
		return
	}
	if handleDispatchView(zid, disp, basket, edPriv, ecdhPriv) {
		fmt.Println("Dispatch processed")
	}
}

// min returns the smaller of two durations.
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

	// Initialize SQLite storage
	var err error
	storage, err = NewSQLiteStorage(*zid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initialize storage: %v\n", err)
		os.Exit(1)
	}

	// Initialize baskets inbox, pending, out, unanswered
	if err := initBaskets(*zid); err != nil {
		fmt.Fprintf(os.Stderr, "Initialize baskets: %v\n", err)
		os.Exit(1)
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

	go checkForMessages(*zid, edPriv, ecdhPriv)
	go pollNotifications(*zid, edPriv)

	reader := bufio.NewReader(os.Stdin)
	for {
		inIds, pendingIds, outIds, unansweredIds, err := LoadBaskets(*zid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load baskets: %v\n", err)
			fmt.Println("\n1. Send Dispatch")
			fmt.Println("2. View Inbox")
			fmt.Println("3. View Pending")
			fmt.Println("4. View Out")
			fmt.Println("5. View Unanswered")
			fmt.Println("6. View Conversations")
			fmt.Println("7. Exit")
			fmt.Print("Choose an option: ")
		}

		fmt.Printf("\n1. Send Dispatch\n")
		fmt.Printf("2. View Inbox [%v]\n", len(inIds))
		fmt.Printf("3. View Pending [%v]\n", len(pendingIds))
		fmt.Printf("4. View Out [%v]\n", len(outIds))
		fmt.Printf("5. View Unanswered [%v]\n", len(unansweredIds))
		fmt.Printf("6. View Conversations\n")
		fmt.Printf("7. View Archived Conversations\n")
		fmt.Printf("8. Exit\n")
		fmt.Print("Choose an option: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			if err := sendNewDispatch(*zid, edPriv); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
		case "2":
			viewBasket(*zid, "inbox", edPriv, ecdhPriv)
		case "3":
			viewBasket(*zid, "pending", edPriv, ecdhPriv)
		case "4":
			viewBasket(*zid, "out", edPriv, ecdhPriv)
		case "5":
			viewBasket(*zid, "unanswered", edPriv, ecdhPriv)
		case "6":
			viewConversations(*zid, ecdhPriv, false)
		case "7":
			viewConversations(*zid, ecdhPriv, true)
		case "8":
			os.Exit(0)
		default:
			fmt.Println("Invalid option")
		}
	}
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

func handleSendRead(disp core.Dispatch, zid string) {
	identity, err := LoadIdentity(getIdentityPath(zid))
	if err != nil {
		fmt.Fprintf(os.Stderr, "couldn't load identity send read: %v\n", err)
		return
	}
	if identity.identity == nil {
		fmt.Fprintf(os.Stderr, "identity not initialized for %s\n", zid)
		return
	}
	edPub, err := base64.StdEncoding.DecodeString(identity.identity.EdPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode ed public key: %v\n", err)
		return
	}
	readReceipt := core.Notification{
		UUID:       uuid.New().String(),
		DispatchID: disp.UUID,
		From:       zid,
		To:         disp.From,
		Type:       "read",
		Timestamp:  time.Now().Unix(),
		PubKey:     base64.StdEncoding.EncodeToString(edPub),
	}
	readReceipt.Signature, err = signNotification(identity.identity, readReceipt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign read receipt: %v\n", err)
		return
	}

	// Store read receipt locally
	if err := storage.StoreReadReceipt(zid, readReceipt); err != nil {
		fmt.Fprintf(os.Stderr, "Store read receipt: %v\n", err)
		return
	}

	// Attempt to send read receipt
	data, err := json.Marshal(readReceipt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal read receipt: %v\n", err)
		return
	}
	resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
	if err != nil || resp.StatusCode != http.StatusOK {
		// Queue if offline or server error
		if err := storage.StorePendingNotification(zid, readReceipt); err != nil {
			fmt.Fprintf(os.Stderr, "Queue read receipt: %v\n", err)
			return
		}
		fmt.Printf("Offline or server error, read receipt queued\n")
		if resp != nil {
			resp.Body.Close()
		}
	} else {
		resp.Body.Close()
	}
}

// processPendingNotifications sends queued notifications when online
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
			fmt.Fprintf(os.Stderr, "Marshal pending notification %s: %v\n", notif.DispatchID, err)
			continue
		}
		resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Send pending notification %s: %v\n", notif.DispatchID, err)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "Send pending notification %s failed: %s\n", notif.DispatchID, resp.Status)
			continue
		}

		// Remove from queue
		if err := storage.RemovePendingNotification(zid, notif.DispatchID, notif.Type); err != nil {
			fmt.Fprintf(os.Stderr, "Remove pending notification %s: %v\n", notif.DispatchID, err)
			continue
		}
		fmt.Printf("Sent queued %s notification for %s\n", notif.Type, notif.DispatchID)
	}
	return nil
}
