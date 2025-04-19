package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"encoding/base64"

	"github.com/jadefox10200/zcomm/core"
)

var (
	dispatchesMu sync.RWMutex
	dispatches   = make(map[string][]core.Dispatch)
	basketsMu    sync.RWMutex
	baskets      = make(map[string]map[string][]string)
	//[zid][]Notification
	pendingNotificationsMu sync.RWMutex
	pendingNotifications  = make(map[string][]core.Notification)
)

// StoreDispatch remains unchanged
func StoreDispatch(zid string, disp core.Dispatch) error {
	path := filepath.Join(zid, "dispatches.json")
	dispatchesMu.Lock()
	defer dispatchesMu.Unlock()

	if dispatches[zid] == nil {
		dispatches[zid] = make([]core.Dispatch, 0)
	}

	dispatches[zid] = append(dispatches[zid], disp)
	data, err := json.MarshalIndent(dispatches, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal dispatches: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create dispatches dir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// LoadDispatches remains unchanged
func LoadDispatches(zid string) ([]core.Dispatch, error) {
	path := filepath.Join(zid, "dispatches.json")
	dispatchesMu.RLock()
	defer dispatchesMu.RUnlock()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read dispatches: %w", err)
	}

	var dispMap map[string][]core.Dispatch
	if err := json.Unmarshal(data, &dispMap); err != nil {
		return nil, fmt.Errorf("unmarshal dispatches: %w", err)
	}

	return dispMap[zid], nil
}

// StoreBasket writes only the basket's UUID array to <zid>/<basket>.json
func StoreBasket(zid, basket, dispID string) error {
	path := filepath.Join(zid, basket+".json")
	basketsMu.Lock()
	defer basketsMu.Unlock()

	if baskets[zid] == nil {
		baskets[zid] = make(map[string][]string)
	}
	if baskets[zid][basket] == nil {
		baskets[zid][basket] = make([]string, 0)
	}

	// Append dispID to the specific basket
	baskets[zid][basket] = append(baskets[zid][basket], dispID)

	// Write only the basket's UUID array to file
	data, err := json.MarshalIndent(baskets[zid][basket], "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", basket, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create %s dir: %w", basket, err)
	}
	return os.WriteFile(path, data, 0600)
}

// LoadBasket reads the basket's UUID array from <zid>/<basket>.json
func LoadBasket(zid, basket string) ([]string, error) {
	path := filepath.Join(zid, basket+".json")
	basketsMu.RLock()
	defer basketsMu.RUnlock()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", basket, err)
	}

	var uuids []string
	if err := json.Unmarshal(data, &uuids); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", basket, err)
	}

	return uuids, nil
}

// MoveMessage updates individual basket files
func MoveMessage(zid, fromBasket, toBasket, dispID string) error {
	basketsMu.Lock()
	defer basketsMu.Unlock()

	if baskets[zid] == nil {
		baskets[zid] = make(map[string][]string)
	}
	if baskets[zid][fromBasket] == nil {
		baskets[zid][fromBasket] = make([]string, 0)
	}
	if baskets[zid][toBasket] == nil {
		baskets[zid][toBasket] = make([]string, 0)
	}

	// Remove from fromBasket
	var newFromList []string
	for _, id := range baskets[zid][fromBasket] {
		if id != dispID {
			newFromList = append(newFromList, id)
		}
	}
	baskets[zid][fromBasket] = newFromList

	// Add to toBasket
	baskets[zid][toBasket] = append(baskets[zid][toBasket], dispID)

	// Write fromBasket
	fromPath := filepath.Join(zid, fromBasket+".json")
	fromData, err := json.MarshalIndent(baskets[zid][fromBasket], "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", fromBasket, err)
	}
	if err := os.MkdirAll(filepath.Dir(fromPath), 0700); err != nil {
		return fmt.Errorf("create %s dir: %w", fromBasket, err)
	}
	if err := os.WriteFile(fromPath, fromData, 0600); err != nil {
		return fmt.Errorf("write %s: %w", fromBasket, err)
	}

	// Write toBasket
	toPath := filepath.Join(zid, toBasket+".json")
	toData, err := json.MarshalIndent(baskets[zid][toBasket], "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", toBasket, err)
	}
	if err := os.MkdirAll(filepath.Dir(toPath), 0700); err != nil {
		return fmt.Errorf("create %s dir: %w", toBasket, err)
	}
	if err := os.WriteFile(toPath, toData, 0600); err != nil {
		return fmt.Errorf("write %s: %w", toBasket, err)
	}

	return nil
}

// RemoveMessage updates only the specified basket file
func RemoveMessage(zid, basket, dispID string) error {
	path := filepath.Join(zid, basket+".json")
	basketsMu.Lock()
	defer basketsMu.Unlock()

	if baskets[zid] == nil {
		return nil
	}

	var newList []string
	for _, id := range baskets[zid][basket] {
		if id != dispID {
			newList = append(newList, id)
		}
	}
	baskets[zid][basket] = newList

	data, err := json.MarshalIndent(baskets[zid][basket], "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", basket, err)
	}
	return os.WriteFile(path, data, 0600)
}

// StoreConversation remains unchanged
func StoreConversation(zid, conID, dispID string, seqNo int, subject string) error {
	path := filepath.Join(zid, "conversations.json")
	dispatchesMu.Lock()
	defer dispatchesMu.Unlock()

	var convs []Conversation
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read conversations: %w", err)
		}
		if err := json.Unmarshal(data, &convs); err != nil {
			return fmt.Errorf("unmarshal conversations: %w", err)
		}
	}

	var conv *Conversation
	for i, c := range convs {
		if c.ConID == conID {
			conv = &convs[i]
			break
		}
	}
	if conv == nil {
		convs = append(convs, Conversation{
			ConID:      conID,
			Subject:    subject,
			Dispatches: nil,
			Ended:      false,
		})
		conv = &convs[len(convs)-1]
	}

	conv.Dispatches = append(conv.Dispatches, struct {
		DispID string
		SeqNo  int
	}{DispID: dispID, SeqNo: seqNo})

	data, err := json.MarshalIndent(convs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal conversations: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create conversations dir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// LoadConversations remains unchanged
func LoadConversations(zid string) ([]Conversation, error) {
	path := filepath.Join(zid, "conversations.json")
	dispatchesMu.RLock()
	defer dispatchesMu.RUnlock()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read conversations: %w", err)
	}

	var convs []Conversation
	if err := json.Unmarshal(data, &convs); err != nil {
		return nil, fmt.Errorf("unmarshal conversations: %w", err)
	}

	return convs, nil
}

// Conversation struct remains unchanged as requested
type Conversation struct {
	ConID      string
	Subject    string
	Dispatches []struct {
		DispID string
		SeqNo  int
	}
	Ended bool
}

type identityStore struct {
	identity *Identity
}

// StorePendingConfirmation queues a confirmation for later sending
func StorePendingNotification(myID string, notif core.Notification) error {
	path := filepath.Join(myID, "pending_notifications.json")
	pendingNotificationsMu.Lock()
	defer pendingNotificationsMu.Unlock()

	if pendingNotifications[myID] == nil {
		pendingNotifications[myID] = make([]core.Notification, 0)
	}

	// Avoid duplicates
	for _, existing := range pendingNotifications[myID] {
		if existing.UUID == notif.UUID {
			return nil // Already queued
		}
	}

	pendingNotifications[myID] = append(pendingNotifications[myID], notif)

	data, err := json.MarshalIndent(pendingNotifications[myID], "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pending_notifications: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create pending_notifications dir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// LoadPendingConfirmations loads queued notifications
func LoadPendingNotifications(zid string) ([]core.Notification, error) {
	path := filepath.Join(zid, "pending_notifications.json")
	pendingNotificationsMu.RLock()
	defer pendingNotificationsMu.RUnlock()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pending_notifications: %w", err)
	}

	var notifs []core.Notification
	if err := json.Unmarshal(data, &notifs); err != nil {
		return nil, fmt.Errorf("unmarshal pending_notifications: %w", err)
	}

	return notifs, nil
}

// RemovePendingConfirmation removes a sent confirmation
func RemovePendingNotification(zid, notifID, notifType string) error {
	path := filepath.Join(zid, "pending_notifications.json")
	pendingNotificationsMu.Lock()
	defer pendingNotificationsMu.Unlock()

	if pendingNotifications[zid] == nil {
		return nil
	}

	var newList []core.Notification
	for _, notif := range pendingNotifications[zid] {
		if !(notif.UUID == notifID) {
			newList = append(newList, notif)
		}
	}
	pendingNotifications[zid] = newList

	data, err := json.MarshalIndent(pendingNotifications[zid], "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pending_notifications: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// StoreReadReceipt saves a ReadConfirmation notification to read_receipts.json.
//StoreReadReceipt(zid, thisDisp, notif)
func StoreReadReceipt(zid string, notif core.Notification) error {
    if zid == "" || notif.Type != "read" {
        return fmt.Errorf("invalid read receipt data")
    }
    pubKey, err := base64.StdEncoding.DecodeString(notif.PubKey)
    if err != nil {
        return fmt.Errorf("decode public key: %w", err)
    }
    if !verifyNotification(notif, pubKey) {
        return fmt.Errorf("invalid notification signature")
    }
    dir := filepath.Join(zid)
    filename := filepath.Join(dir, "read_receipts.json")
    if err := os.MkdirAll(dir, 0700); err != nil {
        return fmt.Errorf("create directory %s: %w", dir, err)
    }
    var receipts []core.Notification
    data, err := os.ReadFile(filename)
    if err == nil {
        if err := json.Unmarshal(data, &receipts); err != nil {
            return fmt.Errorf("unmarshal read receipts: %w", err)
        }
    } else if !os.IsNotExist(err) {
        return fmt.Errorf("read read_receipts.json: %w", err)
    }
    for _, r := range receipts {
        if r.UUID == notif.UUID {
            return nil
        }
    }
    receipts = append(receipts, notif)
    data, err = json.MarshalIndent(receipts, "", "  ")
    if err != nil {
        return fmt.Errorf("marshal read receipts: %w", err)
    }
    if err := os.WriteFile(filename, data, 0600); err != nil {
        return fmt.Errorf("write read_receipts.json: %w", err)
    }
    return nil
}