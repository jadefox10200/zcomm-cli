package main

import (
	"fmt"
	"time"

	"github.com/jadefox10200/zcomm/core"
)

func main() {
	msg := core.ZMessage{
		From:      "alice",
		To:        "bob",
		Timestamp: time.Now().Unix(),
		Type:      "text",
		Body:      "This is a test message",
		Signature: "dummy-signature",
		Hash:      "hash1",
		PrevHash:  "",
		Nonce:     "nonce123",
	}

	err := StoreInboxMessage(msg)
	if err != nil {
		fmt.Println("Failed to store inbox message:", err)
	} else {
		fmt.Println("Stored inbox message successfully.")
	}

	msg.Hash = "hash2"
	msg.Body = "This is a pending message"
	err = StorePendingMessage(msg)
	if err != nil {
		fmt.Println("Failed to store pending message:", err)
	} else {
		fmt.Println("Stored pending message successfully.")
	}

	msg.Hash = "hash3"
	msg.Body = "This is a sent message"
	err = StoreSentMessage(msg)
	if err != nil {
		fmt.Println("Failed to store sent message:", err)
	} else {
		fmt.Println("Stored sent message successfully.")
	}
}
