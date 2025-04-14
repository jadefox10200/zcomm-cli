package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/jadefox10200/zcomm/core"
)

const baseDir = "zcomm_storage"

func storeMessage(folder string, msg core.ZMessage) error {
	dirPath := filepath.Join(baseDir, folder)
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return err
	}

	filename := filepath.Join(dirPath, msg.Hash + ".json")
	data, err := json.MarshalIndent(msg, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0600)
}

func loadMessages(folder string) ([]core.ZMessage, error) {
	dirPath := filepath.Join(baseDir, folder)
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var messages []core.ZMessage
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := ioutil.ReadFile(filepath.Join(dirPath, file.Name()))
		if err != nil {
			continue
		}
		var msg core.ZMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		messages = append(messages, msg)
	}
	return messages, nil
}

// --- Helper wrappers ---
func StoreInboxMessage(msg core.ZMessage) error {
	return storeMessage("inbox", msg)
}

func StorePendingMessage(msg core.ZMessage) error {
	return storeMessage("pending", msg)
}

func StoreSentMessage(msg core.ZMessage) error {
	return storeMessage("outbox", msg)
}

func LoadInboxMessages() ([]core.ZMessage, error) {
	return loadMessages("inbox")
}

func LoadPendingMessages() ([]core.ZMessage, error) {
	return loadMessages("pending")
}

func LoadSentMessages() ([]core.ZMessage, error) {
	return loadMessages("outbox")
}
