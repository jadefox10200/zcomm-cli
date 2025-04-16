package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/jadefox10200/zcomm/core"
)

var (
	storageMu sync.RWMutex
)

// appendMessage appends a dispatch to a file without locking (caller must lock).
func appendMessage(path string, dispatch core.Dispatch) error {
	var dispatches []core.Dispatch
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, &dispatches); err != nil {
				return err
			}
		}
	}

	dispatches = append(dispatches, dispatch)

	data, err := json.MarshalIndent(dispatches, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func StoreInboxMessage(zid string, dispatch core.Dispatch) error {
	storageMu.Lock()
	defer storageMu.Unlock()
	return appendMessage(filepath.Join(zid, "inbox.json"), dispatch)
}

func StoreSentMessage(zid string, dispatch core.Dispatch) error {
	storageMu.Lock()
	defer storageMu.Unlock()
	return appendMessage(filepath.Join(zid, "sent.json"), dispatch)
}

func StorePendingMessage(zid string, dispatch core.Dispatch) error {
	storageMu.Lock()
	defer storageMu.Unlock()
	return appendMessage(filepath.Join(zid, "pending.json"), dispatch)
}

func StoreOutMessage(zid string, dispatch core.Dispatch) error {
	storageMu.Lock()
	defer storageMu.Unlock()
	return appendMessage(filepath.Join(zid, "out.json"), dispatch)
}

func MoveMessage(zid, fromBasket, toBasket string, dispatch core.Dispatch) error {
	storageMu.Lock()
	defer storageMu.Unlock()

	fromPath := filepath.Join(zid, fromBasket+".json")
	var fromDispatches []core.Dispatch
	if _, err := os.Stat(fromPath); err == nil {
		data, err := os.ReadFile(fromPath)
		if err != nil {
			return err
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, &fromDispatches); err != nil {
				return err
			}
		}
	}

	var updatedFrom []core.Dispatch
	for _, d := range fromDispatches {
		if d.Timestamp != dispatch.Timestamp || d.ConversationID != dispatch.ConversationID {
			updatedFrom = append(updatedFrom, d)
		}
	}

	data, err := json.MarshalIndent(updatedFrom, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(fromPath, data, 0600); err != nil {
		return err
	}

	return appendMessage(filepath.Join(zid, toBasket+".json"), dispatch)
}

func LoadInboxMessages(zid string) ([]core.Dispatch, error) {
	return loadMessages(filepath.Join(zid, "inbox.json"))
}

func LoadSentMessages(zid string) ([]core.Dispatch, error) {
	return loadMessages(filepath.Join(zid, "sent.json"))
}

func LoadPendingMessages(zid string) ([]core.Dispatch, error) {
	return loadMessages(filepath.Join(zid, "pending.json"))
}

func LoadOutMessages(zid string) ([]core.Dispatch, error) {
	return loadMessages(filepath.Join(zid, "out.json"))
}

func loadMessages(path string) ([]core.Dispatch, error) {
	storageMu.Lock()
	defer storageMu.Unlock()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var dispatches []core.Dispatch
	if len(data) == 0 {
		return dispatches, nil
	}

	if err := json.Unmarshal(data, &dispatches); err != nil {
		return nil, err
	}
	return dispatches, nil
}