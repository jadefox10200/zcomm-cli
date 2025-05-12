// cmd/client/storage.go
package main

import (
	"bufio"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"regexp"

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
	LoadBasketDispatches(zid, basket string) ([]core.BasketDispatch, error)
	LoadBasket(zid, basket string) ([]string, error)
	// LoadBaskets(zid, basket string) ([]string, error)
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
	GetDispatch(dispatchID string) (core.Dispatch, error) // Added
	HandleOutBasketDispatch(zid string, disp core.Dispatch)
	ViewConversations(zid string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte, encryptionKey []byte, archived bool) bool

	AddContact(zid, alias, contactZID, edPub, ecdhPub string) error
	RemoveContact(zid, alias string) error
	ListContacts(zid string) ([]Contact, error)
	ResolveAlias(zid, alias string) (string, error)
	GetContactPublicKeys(zid, contactZID string) (edPub, ecdhPub string, err error)
}

type Conversation struct {
	ConID   string `db:"con_id"`
	Subject string `db:"subject"`
	// WithZid    string `db:"with_zid"`
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
			to_zid TEXT NOT NULL,
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
		CREATE TABLE IF NOT EXISTS Contacts (
			alias TEXT PRIMARY KEY,
			zid TEXT NOT NULL UNIQUE,
			ed_pub TEXT NOT NULL,
			ecdh_pub TEXT NOT NULL,
			last_updated INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_dispatches_conversation_id ON Dispatches(conversation_id);
		CREATE INDEX IF NOT EXISTS idx_dispatches_from_zid ON Dispatches(from_zid);
		CREATE INDEX IF NOT EXISTS idx_dispatches_to_zid ON Dispatches(to_zid);
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
		INSERT INTO Dispatches (uuid, from_zid, to_zid, subject, body, local_nonce, nonce, ephemeral_pub_key, conversation_id, signature, timestamp, is_end)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, disp.UUID, disp.From, disp.To, disp.Subject, disp.Body, disp.LocalNonce, disp.Nonce, disp.EphemeralPubKey, disp.ConversationID, disp.Signature, disp.Timestamp, disp.IsEnd)
	if err != nil {
		return fmt.Errorf("insert dispatch: %w", err)
	}
	return tx.Commit()
}

type dispatchRow struct {
	UUID            string `db:"uuid"`
	FromZid         string `db:"from_zid"`
	ToZid           string `db:"to_zid"`
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
		SELECT uuid, from_zid, to_zid, subject, body, local_nonce, nonce, ephemeral_pub_key, conversation_id, timestamp, is_end
		FROM Dispatches
		WHERE from_zid = ? OR to_zid LIKE ?
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
		disps = append(disps, core.Dispatch{
			UUID:            row.UUID,
			From:            row.FromZid,
			To:              row.ToZid,
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

func (s *SQLiteStorage) LoadBasketDispatches(zid, basket string) ([]core.BasketDispatch, error) {
	var disps []core.BasketDispatch
	err := s.db.Select(&disps, `
		SELECT b.dispatch_id, d.to_zid, d.from_zid, d.subject
		FROM Baskets b
		left join Dispatches d on d.uuid = b.dispatch_id
		WHERE basket_name = ?
	`, basket)
	if err != nil {
		return nil, fmt.Errorf("select basket %s: %w", basket, err)
	}
	return disps, nil
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
	`, conID)
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

// Define struct for conversation list
type ConvSummary struct {
	ConID   string `db:"con_id"`
	Subject string `db:"subject"`
	// WithZid string `db:"with_zid"`
	Ended bool `db:"ended"`
}

// viewConversations lists active or archived conversations and prompts to view one
func (s *SQLiteStorage) ViewConversations(zid string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte, encryptionKey []byte, archived bool) bool {
	// Query conversations
	endedVal := 0
	if archived {
		endedVal = 1
	}
	var convList []ConvSummary
	err := s.db.Select(&convList, `
		SELECT con_id, subject, ended
		FROM Conversations
		WHERE ended = ?
		ORDER BY con_id
	`, endedVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Select conversations (ended=%d): %v\n", endedVal, err)
		return false
	}

	// Display conversations
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
		fmt.Printf("%d. Subject: %s (Status: %s)\n", i+1, conv.Subject, status)
	}

	// Prompt for selection
	fmt.Print("Enter conversation number to view (0 to exit): ")
	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	num, err := strconv.Atoi(choice)
	if err != nil || num < 0 || num > len(convList) {
		fmt.Println("Invalid choice")
		return true // Stay in viewConversations
	}
	if num == 0 {
		return false // Exit to main menu
	}

	// View selected conversation
	conv := convList[num-1]
	return viewConversation(zid, edPriv, ecdhPriv, s, conv.ConID, conv.Subject, encryptionKey, conv.Ended)
}

// viewConversation displays dispatches for a conversation and offers actions
func viewConversation(zid string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte, storage *SQLiteStorage, conID string, subject string, encryptionKey []byte, ended bool) bool {
	localKey := core.DeriveLocalEncryptionKey(ecdhPriv)

	// Fetch dispatches
	type ConvDisplay struct {
		DispatchID string `db:"dispatch_id"`
		SeqNo      int    `db:"seq_no"`
		FromZID    string `db:"from_zid"`
		ToZID      string `db:"to_zid"`
		Subject    string `db:"subject"`
		Body       string `db:"body"`
		LocalNonce string `db:"local_nonce"`
		Nonce      string `db:"nonce"`
		Timestamp  int64  `db:"timestamp"`
		IsEnd      bool   `db:"is_end"`
	}

	var dispatches []ConvDisplay
	err := storage.db.Select(&dispatches, `
		SELECT 
			cd.dispatch_id,
			cd.seq_no,
			d.from_zid,
			d.to_zid,
			d.subject,
			d.body,
			d.local_nonce,
			d.nonce,
			d.timestamp,
			d.is_end
		FROM ConversationDispatches cd
		JOIN Dispatches d ON cd.dispatch_id = d.uuid
		WHERE cd.con_id = ?
		ORDER BY cd.seq_no
	`, conID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Select dispatches for %s: %v\n", conID, err)
		return true // Return to viewConversations
	}

	// Display conversation
	status := "Active"
	if ended {
		status = "Ended"
	}
	fmt.Printf("\nViewing conversation: %s (Status: %s)\n", subject, status)

	if len(dispatches) == 0 {
		fmt.Println("No dispatches found for this conversation")
	} else {
		fmt.Println("Dispatches:")
		for _, cd := range dispatches {
			// Resolve sender alias
			sender := cd.FromZID
			if alias, err := storage.ResolveAlias(zid, cd.FromZID); err == nil {
				sender = alias
			}

			fmt.Printf("Dispatch ID: %s\n", cd.DispatchID)
			fmt.Printf("From: %s\n", sender)
			fmt.Printf("To: %s\n", cd.ToZID)
			fmt.Printf("Subject: %s\n", cd.Subject)

			// Decrypt body if local_nonce exists
			if cd.LocalNonce != "" {
				ciphertext, err := base64.StdEncoding.DecodeString(cd.Body)
				if err != nil {
					fmt.Printf("Body: %s (failed to decode body: %v)\n", cd.Body, err)
					continue
				}
				nonce, err := base64.StdEncoding.DecodeString(cd.LocalNonce)
				if err != nil {
					fmt.Printf("Body: %s (failed to decode local nonce: %v)\n", cd.Body, err)
					continue
				}
				plaintext, err := core.DecryptAESGCM(localKey[:], nonce, ciphertext)
				if err != nil {
					fmt.Printf("Body: %s (local decryption failed: %v)\n", cd.Body, err)
					continue
				}
				fmt.Printf("Body: %s\n", plaintext)
			} else {
				fmt.Printf("Body: %s (unencrypted)\n", cd.Body)
			}

			fmt.Printf("Timestamp: %s\n", time.Unix(cd.Timestamp, 0).Format(time.RFC1123))
			fmt.Println("---")
		}
	}

	// Prompt for actions
	for {
		fmt.Println("\nOptions:")
		if ended {
			fmt.Println("1. Unarchive")
		} else {
			fmt.Println("1. Archive")
		}
		fmt.Println("2. Exit")
		fmt.Print("Select an option: ")

		reader := bufio.NewReader(os.Stdin)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			newEnded := !ended
			err = storage.StoreConversation(zid, conID, "", 0, subject, newEnded)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Update conversation %s: %v\n", conID, err)
				continue
			}
			action := "Archived"
			if !newEnded {
				action = "Unarchived"
			}
			fmt.Printf("Conversation %s\n", action)
			return true // Refresh conversation list

		case "2":
			return true // Return to viewConversations

		default:
			fmt.Println("Invalid option")
		}
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

// Contact represents a contact entry
type Contact struct {
	Alias       string `db:"alias"`
	ZID         string `db:"zid"`
	EdPub       string `db:"ed_pub"`
	EcdhPub     string `db:"ecdh_pub"`
	LastUpdated int64  `db:"last_updated"`
}

// RemoveContact deletes a contact by alias
func (s *SQLiteStorage) RemoveContact(zid, alias string) error {
	alias = strings.ToLower(alias)
	_, err := s.db.Exec(`
		DELETE FROM Contacts WHERE alias = ?
	`, alias)
	if err != nil {
		return fmt.Errorf("delete contact: %w", err)
	}
	return nil
}

// ListContacts retrieves all contacts
func (s *SQLiteStorage) ListContacts(zid string) ([]Contact, error) {
	var contacts []Contact
	err := s.db.Select(&contacts, `
		SELECT alias, zid, ed_pub, ecdh_pub, last_updated
		FROM Contacts
		ORDER BY alias
	`)
	if err != nil {
		return nil, fmt.Errorf("list contacts: %w", err)
	}
	return contacts, nil
}

// ResolveAlias maps an alias to a ZID
// ResolveAlias checks if the input is a ZID or an alias. If it's a ZID, returns it directly.
// If it's an alias, queries the Contacts table to resolve it to a ZID.
// If input == 0, we assume a user is trying to exit rather than resolve. The string "0" is returned with an error.
func (s *SQLiteStorage) ResolveAlias(zid, input string) (string, error) {
	if input == "0" {
		return "0", fmt.Errorf("user entered 0")
	}
	// Define ZID pattern: starts with alphanumeric, followed by alphanumeric, hyphens, or underscores, min 3 chars
	zidPattern := regexp.MustCompile(`^z[0-9]{9,}$`)

	if zidPattern.MatchString(input) {
		// Input matches ZID pattern, return it directly
		// fmt.Printf("regex z pattern matched: Sending back %s\n", input)
		return input, nil
	}

	input = strings.ToLower(input)
	// Input is treated as an alias, query Contacts table
	var contactZID string
	err := s.db.Get(&contactZID, `
		SELECT zid FROM Contacts WHERE alias = ?
	`, input)
	if err != nil {
		return "", fmt.Errorf("resolve alias %q: %w", input, err)
	}

	// fmt.Printf("Using %s to send\n", contactZID)

	return contactZID, nil
}

// GetContactPublicKeys retrieves public keys for a ZID
func (s *SQLiteStorage) GetContactPublicKeys(zid, contactZID string) (edPub, ecdhPub string, err error) {
	var contact Contact
	err = s.db.Get(&contact, `
		SELECT ed_pub, ecdh_pub FROM Contacts WHERE zid = ?
	`, contactZID)
	if err != nil {
		return "", "", fmt.Errorf("get contact public keys: %w", err)
	}
	return contact.EdPub, contact.EcdhPub, nil
}

// AddContact stores a new contact with alias, ZID, and public keys
func (s *SQLiteStorage) AddContact(zid, alias, contactZID, edPub, ecdhPub string) error {
	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	alias = strings.ToLower(alias)
	_, err = tx.Exec(`
		INSERT INTO Contacts (alias, zid, ed_pub, ecdh_pub, last_updated)
		VALUES (?, ?, ?, ?, ?)
	`, alias, contactZID, edPub, ecdhPub, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("insert contact: %w", err)
	}

	return tx.Commit()
}

// GetDispatch retrieves a dispatch by its UUID from the Dispatches table
func (s *SQLiteStorage) GetDispatch(dispatchID string) (core.Dispatch, error) {
	var disp core.Dispatch
	err := s.db.Get(&disp, `
		SELECT uuid, conversation_id, from_zid, to_zid, subject, body, local_nonce, is_end
		FROM Dispatches
		WHERE uuid = ?
	`, dispatchID)
	if err != nil {
		return core.Dispatch{}, fmt.Errorf("get dispatch %s: %w", dispatchID, err)
	}
	return disp, nil
}

// HandleOutBasketDispatch handles a dispatch in the "out" basket, providing a pullback option.
func (s *SQLiteStorage) HandleOutBasketDispatch(zid string, disp core.Dispatch) {
	// fmt.Printf("Dispatch: To: %s, Subject: %s, Body: %s\n", disp.To, disp.Subject, disp.Body)
	fmt.Print("Options: [1] Pullback, [0] Exit: ")
	var choice int
	_, err := fmt.Scanln(&choice)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read choice: %v\n", err)
		return
	}

	if choice == 0 {
		return
	}
	if choice != 1 {
		fmt.Println("Invalid option")
		return
	}

	// Perform pullback operation
	if err := s.pullBack(zid, disp); err != nil {
		fmt.Fprintf(os.Stderr, "Pullback dispatch %s: %v\n", disp.UUID, err)
		return
	}
}

// pullBack performs the pullback operation for a dispatch in the "out" basket.
// STILL NEED TO IMPLEMENT GETTING IT BACK FROM THE SERVER
// pullBack performs the pullback operation for a dispatch in the "out" basket.
func (s *SQLiteStorage) pullBack(zid string, disp core.Dispatch) error {
	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check seq_no in ConversationDispatches
	var seqNo int
	err = tx.Get(&seqNo, `
		SELECT seq_no
		FROM ConversationDispatches
		WHERE dispatch_id = ?
	`, disp.UUID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("dispatch %s not found in ConversationDispatches", disp.UUID)
	}
	if err != nil {
		return fmt.Errorf("get seq_no for dispatch %s: %w", disp.UUID, err)
	}

	// Remove dispatch from out basket
	_, err = tx.Exec(`
		DELETE FROM Baskets
		WHERE basket_name = ? AND dispatch_id = ?
	`, "out", disp.UUID)
	if err != nil {
		return fmt.Errorf("remove dispatch %s from out basket: %w", disp.UUID, err)
	}

	// Remove dispatch from ConversationDispatches
	_, err = tx.Exec(`
		DELETE FROM ConversationDispatches
		WHERE dispatch_id = ?
	`, disp.UUID)
	if err != nil {
		return fmt.Errorf("remove dispatch %s from ConversationDispatches: %w", disp.UUID, err)
	}

	if seqNo == 1 {
		// Archive conversation if seq_no == 1
		var conv Conversation
		err = tx.Get(&conv, `
			SELECT con_id, subject, ended
			FROM Conversations
			WHERE con_id = ?
		`, disp.ConversationID)
		if err == sql.ErrNoRows {
			return fmt.Errorf("conversation %s not found", disp.ConversationID)
		}
		if err != nil {
			return fmt.Errorf("select conversation %s: %w", disp.ConversationID, err)
		}

		_, err = tx.Exec(`
			UPDATE Conversations
			SET ended = ?
			WHERE con_id = ?
		`, true, disp.ConversationID)
		if err != nil {
			return fmt.Errorf("archive conversation %s: %w", disp.ConversationID, err)
		}
		fmt.Printf("Dispatch %s pulled back, conversation %s archived\n", disp.UUID, disp.ConversationID)
	} else {
		// Find the previous dispatch (seq_no - 1) to move back to pending
		var prevDispatchID string
		err = tx.Get(&prevDispatchID, `
			SELECT dispatch_id
			FROM ConversationDispatches
			WHERE con_id = ? AND seq_no = ?
		`, disp.ConversationID, seqNo-1)
		if err == sql.ErrNoRows {
			return fmt.Errorf("previous dispatch for seq_no %d not found", seqNo-1)
		}
		if err != nil {
			return fmt.Errorf("get previous dispatch for seq_no %d: %w", seqNo-1, err)
		}

		// Move previous dispatch to pending basket
		_, err = tx.Exec(`
			INSERT OR REPLACE INTO Baskets (basket_name, dispatch_id)
			VALUES (?, ?)
		`, "pending", prevDispatchID)
		if err != nil {
			return fmt.Errorf("move dispatch %s to pending basket: %w", prevDispatchID, err)
		}
		fmt.Printf("Dispatch %s pulled back, previous dispatch %s moved to pending\n", disp.UUID, prevDispatchID)
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
