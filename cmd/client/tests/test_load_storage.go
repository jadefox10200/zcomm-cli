package main

import (
	"fmt"
	"log"

	"github.com/jadefox10200/zcomm/core"
)

// import your storage functions
// make sure this file is in the same directory as `storage.go`

func printMessages(label string, messages []core.ZMessage) {
	fmt.Printf("=== %s Messages ===\n", label)
	for i, msg := range messages {
		fmt.Printf("[%d] From: %s | To: %s | Type: %s | Body: %s | Timestamp: %d\n",
			i+1, msg.From, msg.To, msg.Type, msg.Body, msg.Timestamp)
	}
	fmt.Println()
}

func main() {
	inbox, err := LoadInboxMessages()
	if err != nil {
		log.Fatal("Error loading inbox messages:", err)
	}
	printMessages("Inbox", inbox)

	pending, err := LoadPendingMessages()
	if err != nil {
		log.Fatal("Error loading pending messages:", err)
	}
	printMessages("Pending", pending)

	sent, err := LoadSentMessages()
	if err != nil {
		log.Fatal("Error loading sent messages:", err)
	}
	printMessages("Sent", sent)
}
