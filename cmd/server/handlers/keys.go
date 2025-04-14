package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/jadefox10200/zcomm/core"
	"github.com/jadefox10200/zcomm/server/storage"
)

func HandlePublishKeys(store *storage.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var keys core.PublicKeys
		if err := json.NewDecoder(r.Body).Decode(&keys); err != nil {
			http.Error(w, "invalid key data", http.StatusBadRequest)
			return
		}
		store.Set(keys.ID, keys)
		w.WriteHeader(http.StatusOK)
	}
}

func HandleFetchKeys(store *storage.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		keys, ok := store.Get(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(keys)
	}
}
