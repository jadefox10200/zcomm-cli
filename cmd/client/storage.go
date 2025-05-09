// cmd/client/storage.go
package main

import (
	"bufio"
	"database/sql"
	"encoding/base64"

	// "encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jadefox10200/zcomm/core"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

// Storage interface and other methods unchanged
// Modified: StoreDispatch, LoadDispatches, viewArchivedConversations

type Storage interface {
	StoreDispatch(zid string, disp core.Dispatch) error
	LoadDispatches(zid string) ([]core.Dispatch, error)
	StoreBasket(zid, basket, dispID string) error
	LoadBasket(zid, basket string) ([]string, error)
	MoveMessage(zid, fromBasket, toBasket, dispID string) error
	RemoveMessage(zid, basket, dispID string) error
	StoreConversation(zid, conID, dispID string, seqNo int, subject string, isEnd bool) error
	//StoreConversation(zid, conID, dispID string, seqNo int, subject string) error
	LoadConversations(zid string) ([]Conversation, error)
	LoadConversation(zid, conID string) (Conversation, error)
	ArchiveConversation(zid, conversationID string, ended bool) error
	UnarchiveConversation(zid, conversationID string) error
	StorePendingNotification(zid string, notif core.Notification) error
	LoadPendingNotifications(zid string) ([]core.Notification, error)
	RemovePendingNotification(zid, notifID, notifType string) error
	StoreReadReceipt(zid string, notif core.Notification) error
	EndConversation(zid, conversationID string, end bool) error
}

type Conversation struct {
	ConID      string `db:"con_id"`
	Subject    string `db:"subject"`
	Dispatches []struct {
		DispID string
		SeqNo  int
	}
	Ended bool `db:"ended"`
}

type SQLiteStorage struct {
	db *sqlx.DB
}

func NewSQLiteStorage(zid string) (*SQLiteStorage, error) {
	dbPath := filepath.Join(zid, "zcomm.db")
	if err := os.MkdirAll(zid, 0700); err != nil {
		return nil, fmt.Errorf("create directory %s: %w", zid, err)
	}
	db, err := sqlx.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", dbPath, err)
	}
	_, err = db.Exec("PRAGMA journal_mode=WAL;")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS Conversations (
			con_id TEXT PRIMARY KEY,
			subject TEXT NOT NULL,
			ended BOOLEAN NOT NULL DEFAULT FALSE
		);
		CREATE TABLE IF NOT EXISTS Dispatches (
			uuid TEXT PRIMARY KEY,
			from_zid TEXT NOT NULL,
			to_zids TEXT NOT NULL,
			subject TEXT NOT NULL,
			body TEXT NOT NULL,
			local_nonce TEXT, -- Added for local encryption
			nonce TEXT NOT NULL,
			ephemeral_pub_key TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			signature TEXT NOT NULL,
			timestamp INTEGER NOT NULL,
			is_end BOOLEAN NOT NULL DEFAULT FALSE,
			FOREIGN KEY (conversation_id) REFERENCES Conversations(con_id)
		);
		CREATE TABLE IF NOT EXISTS ConversationDispatches (
			con_id TEXT,
			dispatch_id TEXT,
			seq_no INTEGER NOT NULL,
			PRIMARY KEY (con_id, dispatch_id),
			FOREIGN KEY (con_id) REFERENCES Conversations(con_id),
			FOREIGN KEY (dispatch_id) REFERENCES Dispatches(uuid)
		);
		CREATE TABLE IF NOT EXISTS Baskets (
			basket_name TEXT NOT NULL,
			dispatch_id TEXT NOT NULL,
			PRIMARY KEY (basket_name, dispatch_id),
			FOREIGN KEY (dispatch_id) REFERENCES Dispatches(uuid)
		);
		CREATE TABLE IF NOT EXISTS PendingNotifications (
			uuid TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			signature TEXT NOT NULL,
			dispatch_id TEXT NOT NULL,
			timestamp INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS ReadReceipts (
			uuid TEXT PRIMARY KEY,
			dispatch_id TEXT NOT NULL,
			signature TEXT NOT NULL,
			timestamp INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_dispatches_conversation_id ON Dispatches(conversation_id);
		CREATE INDEX IF NOT EXISTS idx_dispatches_from_zid ON Dispatches(from_zid);
		CREATE INDEX IF NOT EXISTS idx_dispatches_to_zids ON Dispatches(to_zids);
		CREATE INDEX IF NOT EXISTS idx_conversation_dispatches_con_id ON ConversationDispatches(con_id);
		CREATE INDEX IF NOT EXISTS idx_baskets_dispatch_id ON Baskets(dispatch_id);
		CREATE INDEX IF NOT EXISTS idx_conversations_ended ON Conversations(ended);
		CREATE INDEX IF NOT EXISTS idx_dispatches_timestamp ON Dispatches(timestamp);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create tables: %w", err)
	}
	return &SQLiteStorage{db: db}, nil
}

func (s *SQLiteStorage) StoreDispatch(zid string, disp core.Dispatch) error {
	if _, err := uuid.Parse(disp.UUID); err != nil {
		return fmt.Errorf("invalid uuid: %w", err)
	}
	if _, err := uuid.Parse(disp.ConversationID); err != nil {
		return fmt.Errorf("invalid conversation_id: %w", err)
	}
	if disp.Timestamp <= 0 {
		return fmt.Errorf("invalid timestamp: %d", disp.Timestamp)
	}
	if _, err := base64.StdEncoding.DecodeString(disp.Body); err != nil {
		return fmt.Errorf("invalid body base64: %w", err)
	}
	if _, err := base64.StdEncoding.DecodeString(disp.Nonce); err != nil && disp.Nonce != "" {
		return fmt.Errorf("invalid nonce base64: %w", err)
	}
	if _, err := base64.StdEncoding.DecodeString(disp.EphemeralPubKey); err != nil && disp.EphemeralPubKey != "" {
		return fmt.Errorf("invalid ephemeral_pub_key base64: %w", err)
	}
	if disp.LocalNonce != "" {
		if _, err := base64.StdEncoding.DecodeString(disp.LocalNonce); err != nil {
			return fmt.Errorf("invalid local_nonce base64: %w", err)
		}
	}

	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`
		INSERT INTO Dispatches (uuid, from_zid, to_zids, subject, body, local_nonce, nonce, ephemeral_pub_key, conversation_id, signature, timestamp, is_end)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, disp.UUID, disp.From, strings.Join(disp.To, ","), disp.Subject, disp.Body, disp.LocalNonce, disp.Nonce, disp.EphemeralPubKey, disp.ConversationID, disp.Signature, disp.Timestamp, disp.IsEnd)
	if err != nil {
		return fmt.Errorf("insert dispatch: %w", err)
	}
	return tx.Commit()
}

type dispatchRow struct {
	UUID            string `db:"uuid"`
	FromZid         string `db:"from_zid"`
	ToZids          string `db:"to_zids"`
	Subject         string `db:"subject"`
	Body            string `db:"body"`
	LocalNonce      string `db:"local_nonce"`
	Nonce           string `db:"nonce"`
	EphemeralPubKey string `db:"ephemeral_pub_key"`
	ConversationID  string `db:"conversation_id"`
	Timestamp       int64  `db:"timestamp"`
	IsEnd           bool   `db:"is_end"`
}

func (s *SQLiteStorage) LoadDispatches(zid string) ([]core.Dispatch, error) {
	var rows []dispatchRow
	err := s.db.Select(&rows, `
		SELECT uuid, from_zid, to_zids, subject, body, local_nonce, nonce, ephemeral_pub_key, conversation_id, timestamp, is_end
		FROM Dispatches
		WHERE from_zid = ? OR to_zids LIKE ?
	`, zid, "%"+zid+"%")
	if err != nil {
		return nil, fmt.Errorf("select dispatches: %w", err)
	}
	disps := make([]core.Dispatch, 0, len(rows))
	for _, row := range rows {
		if _, err := uuid.Parse(row.UUID); err != nil {
			fmt.Fprintf(os.Stderr, "Skipping dispatch with invalid uuid: %s\n", row.UUID)
			continue
		}
		if _, err := uuid.Parse(row.ConversationID); err != nil {
			fmt.Fprintf(os.Stderr, "Skipping dispatch with invalid conversation_id: %s\n", row.ConversationID)
			continue
		}
		if row.Timestamp <= 0 {
			fmt.Fprintf(os.Stderr, "Skipping dispatch with invalid timestamp: %d, uuid: %s\n", row.Timestamp, row.UUID)
			continue
		}
		var to []string
		if row.ToZids != "" {
			to = strings.Split(row.ToZids, ",")
		}
		disps = append(disps, core.Dispatch{
			UUID:            row.UUID,
			From:            row.FromZid,
			To:              to,
			Subject:         row.Subject,
			Body:            row.Body,
			LocalNonce:      row.LocalNonce,
			Nonce:           row.Nonce,
			EphemeralPubKey: row.EphemeralPubKey,
			ConversationID:  row.ConversationID,
			Timestamp:       row.Timestamp,
			IsEnd:           row.IsEnd,
		})
	}
	if len(disps) == 0 && len(rows) > 0 {
		return nil, fmt.Errorf("all dispatches skipped due to invalid data")
	}
	return disps, nil
}

func (s *SQLiteStorage) StoreBasket(zid, basket, dispID string) error {
	_, err := s.db.Exec(`
		INSERT INTO Baskets (basket_name, dispatch_id)
		VALUES (?, ?)
	`, basket, dispID)
	if err != nil {
		return fmt.Errorf("insert basket %s: %w", basket, err)
	}
	return nil
}

func (s *SQLiteStorage) LoadBasket(zid, basket string) ([]string, error) {
	var uuids []string
	err := s.db.Select(&uuids, `
		SELECT dispatch_id
		FROM Baskets
		WHERE basket_name = ?
	`, basket)
	if err != nil {
		return nil, fmt.Errorf("select basket %s: %w", basket, err)
	}
	return uuids, nil
}

func (s *SQLiteStorage) MoveMessage(zid, fromBasket, toBasket, dispID string) error {
	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`
		DELETE FROM Baskets
		WHERE basket_name = ? AND dispatch_id = ?
	`, fromBasket, dispID)
	if err != nil {
		return fmt.Errorf("delete from basket %s: %w", fromBasket, err)
	}
	_, err = tx.Exec(`
		INSERT INTO Baskets (basket_name, dispatch_id)
		VALUES (?, ?)
	`, toBasket, dispID)
	if err != nil {
		return fmt.Errorf("insert into basket %s: %w", toBasket, err)
	}
	return tx.Commit()
}

func (s *SQLiteStorage) RemoveMessage(zid, basket, dispID string) error {
	_, err := s.db.Exec(`
		DELETE FROM Baskets
		WHERE basket_name = ? AND dispatch_id = ?
	`, basket, dispID)
	if err != nil {
		return fmt.Errorf("delete from basket %s: %w", basket, err)
	}
	return nil
}

// StoreConversation stores or updates a conversation and its dispatch.
func (s *SQLiteStorage) StoreConversation(zid, conID, dispID string, seqNo int, subject string, isEnd bool) error {
	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	var exists bool
	err = tx.Get(&exists, "SELECT EXISTS(SELECT 1 FROM Conversations WHERE con_id = ?)", conID)
	if err != nil {
		return fmt.Errorf("check conversation exists: %w", err)
	}

	// fmt.Printf("StoreConversation: conID=%s, dispID=%s, seqNo=%d, subject=%s, isEnd=%v, exists=%v, currentEnded=%v\n",
	// conID, dispID, seqNo, subject, isEnd, exists, isEnd)

	if !exists {
		// Insert new conversation
		_, err = tx.Exec(`
			INSERT INTO Conversations (con_id, subject, ended)
			VALUES (?, ?, ?)
		`, conID, subject, isEnd)
		if err != nil {
			return fmt.Errorf("insert conversation: %w", err)
		}
	} else {
		// Update subject and ended status
		_, err = tx.Exec(`
			UPDATE Conversations
			SET ended = ?
			WHERE con_id = ?
		`, isEnd, conID)
		if err != nil {
			return fmt.Errorf("update conversation: %w", err)
		}
	}

	if dispID != "" {
		// Insert dispatch into conversation
		_, err = tx.Exec(`
			INSERT INTO ConversationDispatches (con_id, dispatch_id, seq_no)
			VALUES (?, ?, ?)
		`, conID, dispID, seqNo)
		if err != nil {
			return fmt.Errorf("insert conversation dispatch: %w", err)
		}
	}

	return tx.Commit()
}

// func (s *SQLiteStorage) StoreConversation(zid, conID, dispID string, seqNo int, subject string) error {
// 	tx, err := s.db.Beginx()
// 	if err != nil {
// 		return fmt.Errorf("begin transaction: %w", err)
// 	}
// 	defer tx.Rollback()
// 	_, err = tx.Exec(`
// 		INSERT OR REPLACE INTO Conversations (con_id, subject, ended)
// 		VALUES (?, ?, (SELECT ended FROM Conversations WHERE con_id = ?))
// 	`, conID, subject, conID)
// 	if err != nil {
// 		return fmt.Errorf("insert conversation: %w", err)
// 	}
// 	if dispID != "" {
// 		_, err = tx.Exec(`
// 			INSERT INTO ConversationDispatches (con_id, dispatch_id, seq_no)
// 			VALUES (?, ?, ?)
// 		`, conID, dispID, seqNo)
// 		if err != nil {
// 			return fmt.Errorf("insert conversation dispatch: %w", err)
// 		}
// 	}
// 	return tx.Commit()
// }

// LoadConversation loads a single conversation by con_id for the given zid.
func (s *SQLiteStorage) LoadConversation(zid, conID string) (Conversation, error) {
	var conv Conversation
	err := s.db.Get(&conv, `
		SELECT con_id, subject, ended
		FROM Conversations
		WHERE con_id = ?
	`, conID)
	if err == sql.ErrNoRows {
		// Return an empty Conversation if not found
		return Conversation{}, nil
	}
	if err != nil {
		return Conversation{}, fmt.Errorf("select conversation %s: %w", conID, err)
	}

	var dispatches []struct {
		DispID string `db:"dispatch_id"`
		SeqNo  int    `db:"seq_no"`
	}
	err = s.db.Select(&dispatches, `
		SELECT dispatch_id, seq_no
		FROM ConversationDispatches
		WHERE con_id = ?
		ORDER BY seq_no
	`, zid, conID)
	if err != nil && err != sql.ErrNoRows {
		return Conversation{}, fmt.Errorf("select dispatches for %s: %w", conID, err)
	}

	conv.Dispatches = make([]struct {
		DispID string
		SeqNo  int
	}, len(dispatches))
	for i, d := range dispatches {
		conv.Dispatches[i] = struct {
			DispID string
			SeqNo  int
		}{d.DispID, d.SeqNo}
	}

	return conv, nil
}

func (s *SQLiteStorage) LoadConversations(zid string) ([]Conversation, error) {
	var convs []Conversation
	err := s.db.Select(&convs, `
		SELECT con_id, subject, ended
		FROM Conversations
	`)
	if err != nil {
		return nil, fmt.Errorf("select conversations: %w", err)
	}
	for i, conv := range convs {
		var dispatches []struct {
			DispID string `db:"dispatch_id"`
			SeqNo  int    `db:"seq_no"`
		}
		err := s.db.Select(&dispatches, `
			SELECT dispatch_id, seq_no
			FROM ConversationDispatches
			WHERE con_id = ?
			ORDER BY seq_no
		`, conv.ConID)
		if err != nil {
			return nil, fmt.Errorf("select dispatches for %s: %w", conv.ConID, err)
		}
		conv.Dispatches = make([]struct {
			DispID string
			SeqNo  int
		}, len(dispatches))
		for j, d := range dispatches {
			conv.Dispatches[j] = struct {
				DispID string
				SeqNo  int
			}{d.DispID, d.SeqNo}
		}
		convs[i] = conv
	}
	return convs, nil
}

func (s *SQLiteStorage) EndConversation(zid, conversationID string, end bool) error {
	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	var conv Conversation
	err = tx.Get(&conv, `
        SELECT con_id, subject, ended
        FROM Conversations
        WHERE con_id = ?
    `, conversationID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("conversation %s not found", conversationID)
	} else if err != nil {
		return fmt.Errorf("select conversation: %w", err)
	}

	_, err = tx.Exec(`
        UPDATE Conversations
        SET ended = ?
        WHERE con_id = ?
    `, end, conversationID)
	if err != nil {
		return fmt.Errorf("update conversation ended: %w", err)
	}

	return tx.Commit()
}

func (s *SQLiteStorage) ArchiveConversation(zid, conversationID string, ended bool) error {
	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	var conv Conversation
	err = tx.Get(&conv, `
        SELECT con_id, subject, ended
        FROM Conversations
        WHERE con_id = ?
    `, conversationID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("conversation %s not found", conversationID)
	} else if err != nil {
		return fmt.Errorf("select conversation: %w", err)
	}

	_, err = tx.Exec(`
        UPDATE Conversations
        SET ended = ?
        WHERE con_id = ?
    `, true, conversationID)
	if err != nil {
		return fmt.Errorf("update conversation ended: %w", err)
	}

	return tx.Commit()
}

func (s *SQLiteStorage) UnarchiveConversation(zid, conversationID string) error {
	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	var conv Conversation
	err = tx.Get(&conv, `
        SELECT con_id, subject, ended
        FROM Conversations
        WHERE con_id = ?
    `, conversationID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("conversation %s not found", conversationID)
	} else if err != nil {
		return fmt.Errorf("select conversation: %w", err)
	}

	_, err = tx.Exec(`
        UPDATE Conversations
        SET ended = ?
        WHERE con_id = ?
    `, false, conversationID)
	if err != nil {
		return fmt.Errorf("update conversation ended: %w", err)
	}

	return tx.Commit()
}

// // viewArchivedConversations displays archived conversations and allows viewing their dispatches
// func viewArchivedConversations(zid string, ecdhPriv [32]byte) bool {
// 	storage, err := NewSQLiteStorage(zid)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Initialize storage: %v\n", err)
// 		return false
// 	}
// 	dispatches, err := storage.LoadDispatches(zid)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
// 		return false
// 	}

// 	localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

// 	for {
// 		var archivedConvs []Conversation
// 		err = storage.db.Select(&archivedConvs, `
// 			SELECT con_id, subject, ended
// 			FROM ArchivedConversations
// 		`)
// 		if err != nil {
// 			fmt.Fprintf(os.Stderr, "Select archived conversations: %v\n", err)
// 			return false
// 		}
// 		if len(archivedConvs) == 0 {
// 			fmt.Println("No archived conversations")
// 			return true
// 		}

// 		fmt.Println("Archived Conversations:")
// 		for i, conv := range archivedConvs {
// 			status := "Active"
// 			if conv.Ended {
// 				status = "Ended"
// 			}
// 			participant := "Unknown"
// 			var latestDisp core.Dispatch
// 			maxSeqNo := -1
// 			var convDispatches []struct {
// 				DispID string `db:"dispatch_id"`
// 				SeqNo  int    `db:"seq_no"`
// 			}
// 			err := storage.db.Select(&convDispatches, `
// 				SELECT dispatch_id, seq_no
// 				FROM ConversationDispatches
// 				WHERE con_id = ?
// 				ORDER BY seq_no
// 			`, conv.ConID)
// 			if err != nil {
// 				fmt.Fprintf(os.Stderr, "Select dispatches for %s: %v\n", conv.ConID, err)
// 				continue
// 			}
// 			for _, entry := range convDispatches {
// 				if entry.SeqNo > maxSeqNo {
// 					maxSeqNo = entry.SeqNo
// 					for _, disp := range dispatches {
// 						if disp.UUID == entry.DispID {
// 							latestDisp = disp
// 							break
// 						}
// 					}
// 				}
// 			}
// 			if latestDisp.UUID != "" {
// 				if latestDisp.From == zid {
// 					if len(latestDisp.To) > 0 {
// 						participant = latestDisp.To[0]
// 					}
// 				} else {
// 					participant = latestDisp.From
// 				}
// 			}
// 			fmt.Printf("%d. Subject: %s (With: %s, Status: %s)\n", i+1, conv.Subject, participant, status)
// 		}

// 		fmt.Print("Enter conversation number to view (0 to exit): ")
// 		reader := bufio.NewReader(os.Stdin)
// 		choice, _ := reader.ReadString('\n')
// 		choice = strings.TrimSpace(choice)
// 		num, err := strconv.Atoi(choice)
// 		if err != nil || num < 0 || num > len(archivedConvs) {
// 			fmt.Println("Invalid choice")
// 			continue
// 		}
// 		if num == 0 {
// 			return false
// 		}

// 		conv := archivedConvs[num-1]
// 		status := "Active"
// 		if conv.Ended {
// 			status = "Ended"
// 		}
// 		fmt.Printf("\nViewing conversation: %s (Status: %s)\n", conv.Subject, status)

// 		var convDispatches []struct {
// 			DispID string `db:"dispatch_id"`
// 			SeqNo  int    `db:"seq_no"`
// 		}
// 		err = storage.db.Select(&convDispatches, `
// 			SELECT dispatch_id, seq_no
// 			FROM ConversationDispatches
// 			WHERE con_id = ?
// 			ORDER BY seq_no
// 		`, conv.ConID)
// 		if err != nil {
// 			fmt.Fprintf(os.Stderr, "Select dispatches for %s: %v\n", conv.ConID, err)
// 			continue
// 		}

// 		if len(convDispatches) == 0 {
// 			fmt.Println("No dispatches found for this conversation")
// 			fmt.Println()
// 			continue
// 		}

// 		fmt.Println("Dispatches:")
// 		for _, cd := range convDispatches {
// 			var disp core.Dispatch
// 			for _, d := range dispatches {
// 				if d.UUID == cd.DispID {
// 					disp = d
// 					break
// 				}
// 			}
// 			if disp.UUID == "" {
// 				fmt.Printf("Dispatch %s not found\n", cd.DispID)
// 				continue
// 			}
// 			fmt.Printf("Dispatch ID: %s\n", disp.UUID)
// 			fmt.Printf("From: %s\n", disp.From)
// 			fmt.Printf("To: %s\n", strings.Join(disp.To, ", "))
// 			fmt.Printf("Subject: %s\n", disp.Subject)

// 			// Decrypt using local key if LocalNonce exists
// 			if disp.LocalNonce != "" {
// 				ciphertext, err := base64.StdEncoding.DecodeString(disp.Body)
// 				if err != nil {
// 					fmt.Printf("Body: %s (failed to decode body: %v)\n", disp.Body, err)
// 					continue
// 				}
// 				nonce, err := base64.StdEncoding.DecodeString(disp.LocalNonce)
// 				if err != nil {
// 					fmt.Printf("Body: %s (failed to decode local nonce: %v)\n", disp.Body, err)
// 					continue
// 				}
// 				plaintext, err := core.DecryptAESGCM(localKey[:], nonce, ciphertext)
// 				if err != nil {
// 					fmt.Printf("Body: %s (local decryption failed: %v)\n", disp.Body, err)
// 					continue
// 				}
// 				fmt.Printf("Body: %s\n", plaintext)
// 			} else {
// 				// Legacy data: attempt transmission decryption or display as-is
// 				if disp.Nonce != "" && disp.EphemeralPubKey != "" {
// 					err := decryptDispatch(&disp, ecdhPriv)
// 					if err != nil {
// 						fmt.Printf("Body: %s (transmission decryption failed: %v)\n", disp.Body, err)
// 					} else {
// 						fmt.Printf("Body: %s\n", disp.Body)
// 					}
// 				} else {
// 					fmt.Printf("Body: %s (unencrypted)\n", disp.Body)
// 				}
// 			}

// 			fmt.Printf("Timestamp: %s\n", time.Unix(disp.Timestamp, 0).Format(time.RFC1123))
// 			fmt.Println("---")
// 		}
// 		fmt.Println()
// 	}
// }

// // viewConversations displays all active conversations.
// func viewConversations(zid string) {
// 	convs, err := storage.LoadConversations(zid)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Load conversations: %v\n", err)
// 		return
// 	}
// 	if len(convs) == 0 {
// 		fmt.Println("No conversations")
// 		return
// 	}

// 	dispatches, err := storage.LoadDispatches(zid)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
// 		return
// 	}

// 	type convEntry struct {
// 		ConID      string
// 		Subject    string
// 		Dispatches []struct {
// 			DispID string
// 			SeqNo  int
// 		}
// 		Ended bool
// 	}
// 	convList := make([]convEntry, 0, len(convs))
// 	for _, conv := range convs {
// 		convList = append(convList, convEntry{
// 			ConID:      conv.ConID,
// 			Subject:    conv.Subject,
// 			Dispatches: conv.Dispatches,
// 			Ended:      conv.Ended,
// 		})
// 	}

// 	if len(convList) == 0 {
// 		fmt.Println("No active conversations")
// 		return
// 	}

// 	for i, conv := range convList {
// 		fmt.Printf("\n%d. Subject: %s (ID: %s)\n", i+1, conv.Subject, conv.ConID)
// 		entries := conv.Dispatches
// 		sort.Slice(entries, func(i, j int) bool {
// 			return entries[i].SeqNo < entries[j].SeqNo
// 		})
// 		for _, entry := range entries {
// 			for _, disp := range dispatches {
// 				if disp.UUID == entry.DispID {
// 					fmt.Printf("    %d. From: %s, Subject: %s, Time: %s\n", entry.SeqNo, disp.From, disp.Subject, time.Unix(disp.Timestamp, 0).Format(time.RFC3339))
// 				}
// 			}
// 		}
// 	}

// 	reader := bufio.NewReader(os.Stdin)
// 	fmt.Print("Select conversation number (0 to exit): ")
// 	input, _ := reader.ReadString('\n')
// 	input = strings.TrimSpace(input)
// 	if input == "" || input == "0" {
// 		return
// 	}

// 	num, err := strconv.Atoi(input)
// 	if err != nil || num < 1 || num > len(convList) {
// 		fmt.Println("Invalid selection")
// 		return
// 	}

// 	selectedConv := convList[num-1]
// 	fmt.Println("\nConversation Thread:")
// 	entries := selectedConv.Dispatches
// 	sort.Slice(entries, func(i, j int) bool {
// 		return entries[i].SeqNo < entries[j].SeqNo
// 	})
// 	for _, entry := range entries {
// 		for _, disp := range dispatches {
// 			if disp.UUID == entry.DispID {
// 				fmt.Printf("  %d. From: %s, Subject: %s, Time: %s\n", entry.SeqNo, disp.From, disp.Subject, time.Unix(disp.Timestamp, 0).Format(time.RFC3339))
// 			}
// 		}
// 	}
// 	fmt.Print("Press Enter to continue...")
// 	reader.ReadString('\n')
// }

// viewConversations displays either active or archived conversations based on the archived flag.
// If archived=true, it queries ArchivedConversations; if archived=false, it queries Conversations.
// Displays full conversation details, including decrypted dispatch bodies, for the selected conversation.
// func viewConversations(zid string, ecdhPriv [32]byte, archived bool) bool {
// 	storage, err := NewSQLiteStorage(zid)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Initialize storage: %v\n", err)
// 		return false
// 	}
// 	dispatches, err := storage.LoadDispatches(zid)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
// 		return false
// 	}

// 	localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

// 	for {
// 		var convs []Conversation
// 		if archived {
// 			// Query archived conversations
// 			err = storage.db.Select(&convs, `
//                 SELECT con_id, subject, ended
//                 FROM ArchivedConversations
//             `)
// 			if err != nil {
// 				fmt.Fprintf(os.Stderr, "Select archived conversations: %v\n", err)
// 				return false
// 			}
// 		} else {
// 			// Query active conversations
// 			convs, err = storage.LoadConversations(zid)
// 			if err != nil {
// 				fmt.Fprintf(os.Stderr, "Select active conversations: %v\n", err)
// 				return false
// 			}
// 		}

// 		if len(convs) == 0 {
// 			if archived {
// 				fmt.Println("No archived conversations")
// 			} else {
// 				fmt.Println("No active conversations")
// 			}
// 			return true
// 		}

// 		fmt.Println()
// 		if archived {
// 			fmt.Println("Archived Conversations:")
// 		} else {
// 			fmt.Println("Active Conversations:")
// 		}
// 		for i, conv := range convs {
// 			status := "Active"
// 			if conv.Ended {
// 				status = "Ended"
// 			}
// 			participant := "Unknown"
// 			var latestDisp core.Dispatch
// 			maxSeqNo := -1
// 			var convDispatches []struct {
// 				DispID string `db:"dispatch_id"`
// 				SeqNo  int    `db:"seq_no"`
// 			}
// 			err := storage.db.Select(&convDispatches, `
//                 SELECT dispatch_id, seq_no
//                 FROM ConversationDispatches
//                 WHERE con_id = ?
//                 ORDER BY seq_no
//             `, conv.ConID)
// 			if err != nil {
// 				fmt.Fprintf(os.Stderr, "Select dispatches for %s: %v\n", conv.ConID, err)
// 				continue
// 			}
// 			for _, entry := range convDispatches {
// 				if entry.SeqNo > maxSeqNo {
// 					maxSeqNo = entry.SeqNo
// 					for _, disp := range dispatches {
// 						if disp.UUID == entry.DispID {
// 							latestDisp = disp
// 							break
// 						}
// 					}
// 				}
// 			}
// 			if latestDisp.UUID != "" {
// 				if latestDisp.From == zid {
// 					if len(latestDisp.To) > 0 {
// 						participant = latestDisp.To[0]
// 					}
// 				} else {
// 					participant = latestDisp.From
// 				}
// 			}
// 			fmt.Printf("%d. Subject: %s (With: %s, Status: %s)\n", i+1, conv.Subject, participant, status)
// 		}

// 		fmt.Print("Enter conversation number to view (0 to exit): ")
// 		reader := bufio.NewReader(os.Stdin)
// 		choice, _ := reader.ReadString('\n')
// 		choice = strings.TrimSpace(choice)
// 		num, err := strconv.Atoi(choice)
// 		if err != nil || num < 0 || num > len(convs) {
// 			fmt.Println("Invalid choice")
// 			continue
// 		}
// 		if num == 0 {
// 			return false
// 		}

// 		conv := convs[num-1]
// 		status := "Active"
// 		if conv.Ended {
// 			status = "Ended"
// 		}
// 		fmt.Printf("\nViewing conversation: %s (Status: %s)\n", conv.Subject, status)

// 		var convDispatches []struct {
// 			DispID string `db:"dispatch_id"`
// 			SeqNo  int    `db:"seq_no"`
// 		}
// 		err = storage.db.Select(&convDispatches, `
//             SELECT dispatch_id, seq_no
//             FROM ConversationDispatches
//             WHERE con_id = ?
//             ORDER BY seq_no
//         `, conv.ConID)
// 		if err != nil {
// 			fmt.Fprintf(os.Stderr, "Select dispatches for %s: %v\n", conv.ConID, err)
// 			continue
// 		}

// 		if len(convDispatches) == 0 {
// 			fmt.Println("No dispatches found for this conversation")
// 			fmt.Println()
// 			continue
// 		}

// 		fmt.Println("Dispatches:")
// 		for _, cd := range convDispatches {
// 			var disp core.Dispatch
// 			for _, d := range dispatches {
// 				if d.UUID == cd.DispID {
// 					disp = d
// 					break
// 				}
// 			}
// 			if disp.UUID == "" {
// 				fmt.Printf("Dispatch %s not found\n", cd.DispID)
// 				continue
// 			}
// 			fmt.Printf("Dispatch ID: %s\n", disp.UUID)
// 			fmt.Printf("From: %s\n", disp.From)
// 			fmt.Printf("To: %s\n", strings.Join(disp.To, ", "))
// 			fmt.Printf("Subject: %s\n", disp.Subject)

// 			// Decrypt using local key if LocalNonce exists
// 			if disp.LocalNonce != "" {
// 				ciphertext, err := base64.StdEncoding.DecodeString(disp.Body)
// 				if err != nil {
// 					fmt.Printf("Body: %s (failed to decode body: %v)\n", disp.Body, err)
// 					continue
// 				}
// 				nonce, err := base64.StdEncoding.DecodeString(disp.LocalNonce)
// 				if err != nil {
// 					fmt.Printf("Body: %s (failed to decode local nonce: %v)\n", disp.Body, err)
// 					continue
// 				}
// 				plaintext, err := core.DecryptAESGCM(localKey[:], nonce, ciphertext)
// 				if err != nil {
// 					fmt.Printf("Body: %s (local decryption failed: %v)\n", disp.Body, err)
// 					continue
// 				}
// 				fmt.Printf("Body: %s\n", plaintext)
// 			} else {
// 				//decrypt senders dispatch
// 				if disp.Nonce != "" && disp.EphemeralPubKey != "" {
// 					err := decryptDispatch(&disp, ecdhPriv)
// 					if err != nil {
// 						fmt.Printf("Body: %s (transmission decryption failed: %v)\n", disp.Body, err)
// 					} else {
// 						fmt.Printf("Body: %s\n", disp.Body)
// 					}
// 				} else {
// 					fmt.Printf("Body: %s (unencrypted)\n", disp.Body)
// 				}
// 			}

// 			fmt.Printf("Timestamp: %s\n", time.Unix(disp.Timestamp, 0).Format(time.RFC1123))
// 			fmt.Println("---")
// 		}
// 		fmt.Println()
// 	}
// }

// viewConversations displays either active or archived conversations based on the archived flag.
// Uses a Conversations table with an ended column, with a JOIN and MAX(timestamp) for the summary view.
// viewConversations displays either active or archived conversations based on the archived flag.
// Uses a Conversations table with an ended column, with a CTE for the summary view to avoid aggregate misuse.
func viewConversations(zid string, ecdhPriv [32]byte, archived bool) bool {
	storage, err := NewSQLiteStorage(zid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initialize storage: %v\n", err)
		return false
	}

	localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

	for {
		// Define struct for summary view
		type ConvSummary struct {
			ConID        string `db:"con_id"`
			Subject      string `db:"subject"`
			Ended        bool   `db:"ended"`
			MaxTimestamp int64  `db:"max_timestamp"`
			Participant  string `db:"participant"`
		}

		var convList []ConvSummary
		endedVal := 0
		if archived {
			endedVal = 1
		}

		// Summary query with CTE to find the latest dispatch
		query := `
            SELECT 
                c.con_id,
                c.subject,
                c.ended,
                COALESCE(d.timestamp, 0) AS max_timestamp,
                COALESCE(
                    CASE 
                        WHEN d.from_zid = ? THEN (
                            TRIM(SUBSTR(d.to_zids, 1, INSTR(d.to_zids || ',', ',') - 1))
                        )
                        ELSE d.from_zid 
                    END, 'Unknown'
                ) AS participant
            FROM Conversations c
            LEFT JOIN (
                SELECT 
                    cd.con_id,
                    d.from_zid,
                    d.to_zids,
                    d.timestamp
                FROM ConversationDispatches cd
                JOIN Dispatches d ON cd.dispatch_id = d.uuid
                WHERE cd.dispatch_id IN (
                    SELECT cd2.dispatch_id
                    FROM ConversationDispatches cd2
                    JOIN Dispatches d2 ON cd2.dispatch_id = d2.uuid
                    WHERE cd2.con_id = cd.con_id
                    ORDER BY d2.timestamp DESC
                    LIMIT 1
                )
            ) d ON c.con_id = d.con_id
            WHERE c.ended = ?
            ORDER BY max_timestamp DESC
        `

		err = storage.db.Select(&convList, query, zid, endedVal)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Select conversations (ended=%d): %v\n", endedVal, err)
			return false
		}

		if len(convList) == 0 {
			if archived {
				fmt.Println("No archived conversations")
			} else {
				fmt.Println("No active conversations")
			}
			return true
		}

		fmt.Println()
		if archived {
			fmt.Println("Archived Conversations:")
		} else {
			fmt.Println("Active Conversations:")
		}
		for i, conv := range convList {
			status := "Active"
			if conv.Ended {
				status = "Ended"
			}
			fmt.Printf("%d. Subject: %s (With: %s, Status: %s)\n", i+1, conv.Subject, conv.Participant, status)
		}

		fmt.Print("Enter conversation number to view (0 to exit): ")
		reader := bufio.NewReader(os.Stdin)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		num, err := strconv.Atoi(choice)
		if err != nil || num < 0 || num > len(convList) {
			fmt.Println("Invalid choice")
			continue
		}
		if num == 0 {
			return false
		}

		conv := convList[num-1]
		status := "Active"
		if conv.Ended {
			status = "Ended"
		}
		fmt.Printf("\nViewing conversation: %s (Status: %s)\n", conv.Subject, status)

		// Fetch detailed dispatches for the selected conversation
		type ConvDisplay struct {
			DispatchID      string `db:"dispatch_id"`
			SeqNo           int    `db:"seq_no"`
			FromID          string `db:"from_zid"`
			ToIDs           string `db:"to_zids"`
			DispSubject     string `db:"disp_subject"`
			Body            string `db:"body"`
			Nonce           string `db:"nonce"`
			LocalNonce      string `db:"local_nonce"`
			Timestamp       int64  `db:"timestamp"`
			Signature       string `db:"signature"`
			EphemeralPubKey string `db:"ephemeral_pub_key"`
			IsEnd           bool   `db:"is_end"`
		}

		var dispatches []ConvDisplay
		err = storage.db.Select(&dispatches, `
            SELECT 
                cd.dispatch_id,
                cd.seq_no,
                d.from_zid,
                d.to_zids,
                d.subject AS disp_subject,
                d.body,
                d.nonce,
                d.local_nonce,
                d.timestamp,
                d.ephemeral_pub_key,
                d.is_end
            FROM ConversationDispatches cd
            JOIN Dispatches d ON cd.dispatch_id = d.uuid
            WHERE cd.con_id = ?
            ORDER BY cd.seq_no
        `, conv.ConID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Select dispatches for %s: %v\n", conv.ConID, err)
			continue
		}

		if len(dispatches) == 0 {
			fmt.Println("No dispatches found for this conversation")
			fmt.Println()
			continue
		}

		fmt.Println("Dispatches:")
		for _, cd := range dispatches {
			disp := core.Dispatch{
				UUID:            cd.DispatchID,
				From:            cd.FromID,
				To:              strings.Split(cd.ToIDs, ","), // Assuming to_ids is comma-separated
				Subject:         cd.DispSubject,
				Body:            cd.Body,
				Nonce:           cd.Nonce,
				LocalNonce:      cd.LocalNonce,
				Timestamp:       cd.Timestamp,
				ConversationID:  conv.ConID,
				Signature:       cd.Signature,
				EphemeralPubKey: cd.EphemeralPubKey,
				IsEnd:           cd.IsEnd,
			}

			fmt.Printf("Dispatch ID: %s\n", disp.UUID)
			fmt.Printf("From: %s\n", disp.From)
			fmt.Printf("To: %s\n", strings.Join(disp.To, ", "))
			fmt.Printf("Subject: %s\n", disp.Subject)

			// Decrypt using local key if LocalNonce exists
			if disp.LocalNonce != "" {
				ciphertext, err := base64.StdEncoding.DecodeString(disp.Body)
				if err != nil {
					fmt.Printf("Body: %s (failed to decode body: %v)\n", disp.Body, err)
					continue
				}
				nonce, err := base64.StdEncoding.DecodeString(disp.LocalNonce)
				if err != nil {
					fmt.Printf("Body: %s (failed to decode local nonce: %v)\n", disp.Body, err)
					continue
				}
				plaintext, err := core.DecryptAESGCM(localKey[:], nonce, ciphertext)
				if err != nil {
					fmt.Printf("Body: %s (local decryption failed: %v)\n", disp.Body, err)
					continue
				}
				fmt.Printf("Body: %s\n", plaintext)
			} else {
				// Legacy data: attempt transmission decryption or display as-is
				if disp.Nonce != "" && disp.EphemeralPubKey != "" {
					err := decryptDispatch(&disp, ecdhPriv)
					if err != nil {
						fmt.Printf("Body: %s (transmission decryption failed: %v)\n", disp.Body, err)
					} else {
						fmt.Printf("Body: %s\n", disp.Body)
					}
				} else {
					fmt.Printf("Body: %s (unencrypted)\n", disp.Body)
				}
			}

			fmt.Printf("Timestamp: %s\n", time.Unix(disp.Timestamp, 0).Format(time.RFC1123))
			fmt.Println("---")
		}
		fmt.Println()
	}
}

type notificationRow struct {
	UUID       string `db:"uuid"`
	Type       string `db:"type"`
	PubKey     string `db:"pub_key"`
	Signature  string `db:"signature"`
	DispatchID string `db:"dispatch_id"`
	Timestamp  int64  `db:"timestamp"`
}

func (s *SQLiteStorage) StorePendingNotification(zid string, notif core.Notification) error {
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO PendingNotifications (uuid, type, signature, dispatch_id, timestamp)
		VALUES (?, ?, ?, ?, ?)
	`, notif.UUID, notif.Type, notif.Signature, notif.DispatchID, notif.Timestamp)
	if err != nil {
		return fmt.Errorf("insert pending notification: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) LoadPendingNotifications(zid string) ([]core.Notification, error) {
	var rows []notificationRow
	err := s.db.Select(&rows, `
		SELECT uuid, type, signature, dispatch_id, timestamp
		FROM PendingNotifications
	`)
	if err != nil {
		return nil, fmt.Errorf("select pending notifications: %w", err)
	}
	notifs := make([]core.Notification, len(rows))
	for i, row := range rows {
		notifs[i] = core.Notification{
			UUID:       row.UUID,
			DispatchID: row.DispatchID,
			From:       "",
			To:         "",
			Type:       row.Type,
			Timestamp:  row.Timestamp,
			Signature:  row.Signature,
		}
	}
	return notifs, nil
}

func (s *SQLiteStorage) RemovePendingNotification(zid, notifID, notifType string) error {
	_, err := s.db.Exec(`
		DELETE FROM PendingNotifications
		WHERE uuid = ? AND type = ?
	`, notifID, notifType)
	if err != nil {
		return fmt.Errorf("delete pending notification: %w", err)
	}
	return nil
}

// StoreReadReceipt stores a read receipt in the database.
func (s *SQLiteStorage) StoreReadReceipt(zid string, notif core.Notification) error {
	if zid == "" || notif.Type != "read" {
		return fmt.Errorf("invalid read receipt data")
	}
	keys, err := fetchPublicKeys(notif.From)
	if err != nil {
		return fmt.Errorf("fetch public keys for %s: %w", notif.From, err)
	}
	pubKey, err := base64.StdEncoding.DecodeString(keys.EdPub)
	if err != nil {
		return fmt.Errorf("decode public key for %s: %w", notif.From, err)
	}

	// Log notification for verification
	// notifJSON, _ := json.MarshalIndent(notif, "", "  ")
	// fmt.Printf("Verifying read receipt: %s\n", notifJSON)

	valid, err := core.VerifyNotification(notif, pubKey)
	if err != nil || !valid {
		return fmt.Errorf("invalid notification signature: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT OR IGNORE INTO ReadReceipts (uuid, dispatch_id, signature, timestamp)
		VALUES (?, ?, ?, ?)
	`, notif.UUID, notif.DispatchID, notif.Signature, notif.Timestamp)
	if err != nil {
		return fmt.Errorf("insert read receipt: %w", err)
	}
	return nil
}

// func initBaskets(zid string) error {
// 	storage, err := NewSQLiteStorage(zid)
// 	if err != nil {
// 		return fmt.Errorf("initialize storage: %w", err)
// 	}
// 	basketNames := []string{"in", "out", "pending", "unanswered"}
// 	for _, basket := range basketNames {
// 		uuids, err := storage.LoadBasket(zid, basket)
// 		if err != nil {
// 			return fmt.Errorf("load %s basket: %w", basket, err)
// 		}
// 		if uuids == nil {
// 			uuids = []string{}
// 		}
// 	}
// 	fmt.Fprintf(os.Stderr, "Initialized baskets for %s\n", zid)
// 	return nil
// }
