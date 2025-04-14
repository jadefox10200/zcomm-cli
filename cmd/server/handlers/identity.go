package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jadefox10200/zcomm/cmd/server/storage"
)

func HandleIdentity(identityStore *storage.IdentityStore, keyStore *storage.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var identity storage.Identity
		if err := json.NewDecoder(r.Body).Decode(&identity); err != nil || identity.ID == "" {
			http.Error(w, "Invalid identity", http.StatusBadRequest)
			return
		}

		if err := identityStore.Add(identity); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}

		keyStore.Set(identity.ID, identity.ToPublicKeys())
		if err := keyStore.Save(); err != nil {
			http.Error(w, "Failed to save keys", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Identity registered")
	}
}
