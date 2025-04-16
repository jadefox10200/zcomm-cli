package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jadefox10200/zcomm/core"
)

// StoreDispatch appends an immutable dispatch to dispatches.json.
func StoreDispatch(zid string, disp core.Dispatch) error {
	path := filepath.Join(zid, "dispatches.json")
	var dispatches []core.Dispatch

	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read dispatches: %w", err)
		}
		if err := json.Unmarshal(data, &dispatches); err != nil {
			return fmt.Errorf("unmarshal dispatches: %w", err)
		}
	}

	dispatches = append(dispatches, disp)
	data, err := json.MarshalIndent(dispatches, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal dispatches: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create dispatches dir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// StoreConversation adds a dispatch to a conversation thread.
func StoreConversation(zid, conID, dispID string, seqNo int) error {
	path := filepath.Join(zid, "conversations.json")
	type conversationEntry struct {
		DispID string `json:"dispID"`
		SeqNo  int    `json:"seqNo"`
	}
	type conversation struct {
		ConID      string             `json:"conID"`
		Dispatches []conversationEntry `json:"dispatches"`
	}
	var convs []conversation

	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read conversations: %w", err)
		}
		if err := json.Unmarshal(data, &convs); err != nil {
			return fmt.Errorf("unmarshal conversations: %w", err)
		}
	}

	var conv *conversation
	for i, c := range convs {
		if c.ConID == conID {
			conv = &convs[i]
			break
		}
	}
	if conv == nil {
		conv = &conversation{ConID: conID, Dispatches: []conversationEntry{}}
		convs = append(convs, *conv)
	}

	conv.Dispatches = append(conv.Dispatches, conversationEntry{DispID: dispID, SeqNo: seqNo})
	data, err := json.MarshalIndent(convs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal conversations: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create conversations dir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// StoreBasket adds a DispID to a basket file.
func StoreBasket(zid, basket, dispID string) error {
	path := filepath.Join(zid, basket+".json")
	var dispIDs []string

	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", basket, err)
		}
		if err := json.Unmarshal(data, &dispIDs); err != nil {
			return fmt.Errorf("unmarshal %s: %w", basket, err)
		}
	}

	dispIDs = append(dispIDs, dispID)
	data, err := json.MarshalIndent(dispIDs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", basket, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create %s dir: %w", basket, err)
	}
	return os.WriteFile(path, data, 0600)
}

// LoadBasket retrieves DispIDs from a basket.
func LoadBasket(zid, basket string) ([]string, error) {
	path := filepath.Join(zid, basket+".json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", basket, err)
	}

	var dispIDs []string
	if err := json.Unmarshal(data, &dispIDs); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", basket, err)
	}
	return dispIDs, nil
}

// MoveMessage moves a DispID between baskets.
func MoveMessage(zid, fromBasket, toBasket, dispID string) error {
	// Remove from source
	path := filepath.Join(zid, fromBasket+".json")
	var fromDispIDs []string
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", fromBasket, err)
		}
		if err := json.Unmarshal(data, &fromDispIDs); err != nil {
			return fmt.Errorf("unmarshal %s: %w", fromBasket, err)
		}
	}

	var newFromDispIDs []string
	found := false
	for _, id := range fromDispIDs {
		if id != dispID {
			newFromDispIDs = append(newFromDispIDs, id)
		} else {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("dispatch %s not found in %s", dispID, fromBasket)
	}

	data, err := json.MarshalIndent(newFromDispIDs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", fromBasket, err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", fromBasket, err)
	}

	// Add to destination
	return StoreBasket(zid, toBasket, dispID)
}

// RemoveMessage removes a DispID from a basket.
func RemoveMessage(zid, basket, dispID string) error {
	path := filepath.Join(zid, basket+".json")
	var dispIDs []string
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", basket, err)
		}
		if err := json.Unmarshal(data, &dispIDs); err != nil {
			return fmt.Errorf("unmarshal %s: %w", basket, err)
		}
	}

	var newDispIDs []string
	found := false
	for _, id := range dispIDs {
		if id != dispID {
			newDispIDs = append(newDispIDs, id)
		} else {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("dispatch %s not found in %s", dispID, basket)
	}

	data, err := json.MarshalIndent(newDispIDs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", basket, err)
	}
	return os.WriteFile(path, data, 0600)
}

// LoadDispatches retrieves all dispatches.
func LoadDispatches(zid string) ([]core.Dispatch, error) {
	path := filepath.Join(zid, "dispatches.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read dispatches: %w", err)
	}

	var dispatches []core.Dispatch
	if err := json.Unmarshal(data, &dispatches); err != nil {
		return nil, fmt.Errorf("unmarshal dispatches: %w", err)
	}
	return dispatches, nil
}

// LoadConversations retrieves conversation threads.
func LoadConversations(zid string) ([]struct {
	ConID      string
	Dispatches []struct {
		DispID string
		SeqNo  int
	}
}, error) {
	path := filepath.Join(zid, "conversations.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read conversations: %w", err)
	}

	var convs []struct {
		ConID      string
		Dispatches []struct {
			DispID string
			SeqNo  int
		}
	}
	if err := json.Unmarshal(data, &convs); err != nil {
		return nil, fmt.Errorf("unmarshal conversations: %w", err)
	}
	return convs, nil
}