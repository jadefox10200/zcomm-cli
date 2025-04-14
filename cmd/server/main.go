package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/jadefox10200/zcomm/core"
)

var inbox = make(map[string][]core.ZMessage)

func handleSend(w http.ResponseWriter, r *http.Request) {
	var msg core.ZMessage
	err := json.NewDecoder(r.Body).Decode(&msg)
	if err != nil {
		http.Error(w, "invalid message", http.StatusBadRequest)
		return
	}
	inbox[msg.To] = append(inbox[msg.To], msg)
	fmt.Fprintf(w, "Message delivered")
}

func handleReceive(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("id")
	msgs := inbox[user]
	if len(msgs) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(msgs)
	inbox[user] = []core.ZMessage{} // clear inbox after delivery
}

func main() {
	http.HandleFunc("/send", handleSend)
	http.HandleFunc("/receive", handleReceive)
	
	http.HandleFunc("/publish", handlePublishKeys)
	http.HandleFunc("/pubkey", handleFetchKeys)


	log.Println("ZComm Switchboard server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
