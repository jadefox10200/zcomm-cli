package main

import (
	"encoding/json"
	"net/http"

	"github.com/jadefox10200/zcomm/core"
)
// var users = make(map[string]core.PublicKeys) //maps user ID to ed25519 public key (base64)
var pubKeyDirectory = make(map[string]core.PublicKeys)

func handlePublishKeys(w http.ResponseWriter, r *http.Request) {
	var keys core.PublicKeys
	if err := json.NewDecoder(r.Body).Decode(&keys); err != nil {
		http.Error(w, "invalid key data", http.StatusBadRequest)
		return
	}
	// users[keys.ID] = keys
	pubKeyDirectory[keys.ID] = keys
	w.WriteHeader(http.StatusOK)
	// json.NewEncoder(w).Encode(map[string]string{"status": "published"})
}

func handleFetchKeys(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	keys, ok := pubKeyDirectory[id]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(keys)
}
