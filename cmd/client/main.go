package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"sort"

	"github.com/jadefox10200/zcomm/core"
	"golang.org/x/crypto/curve25519"
)

const serverURL = "http://localhost:8080"

var (
	conversationsMu sync.RWMutex
	conversations   = make(map[string]map[string][]string)
)

func fetchPublicKeys(zid string) (core.PublicKeys, error) {
	resp, err := http.Get(fmt.Sprintf("%s/pubkey?id=%s", serverURL, zid))
	if err != nil {
		return core.PublicKeys{}, fmt.Errorf("fetch keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return core.PublicKeys{}, fmt.Errorf("fetch keys failed: %s", string(body))
	}

	var keys core.PublicKeys
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return core.PublicKeys{}, fmt.Errorf("decode keys: %w", err)
	}
	return keys, nil
}

func loadConversations(zid string) error {
	path := filepath.Join(zid, "conversations.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read conversations: %w", err)
	}

	var convs map[string]map[string][]string
	if err := json.Unmarshal(data, &convs); err != nil {
		return fmt.Errorf("unmarshal conversations: %w", err)
	}

	conversationsMu.Lock()
	defer conversationsMu.Unlock()
	conversations[zid] = convs[zid]
	if conversations[zid] == nil {
		conversations[zid] = make(map[string][]string)
	}
	return nil
}

func saveConversations(zid string) error {
	path := filepath.Join(zid, "conversations.json")
	conversationsMu.RLock()
	defer conversationsMu.RUnlock()

	data, err := json.MarshalIndent(map[string]map[string][]string{zid: conversations[zid]}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal conversations: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create conversations dir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

func checkForMessages(zid string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) {
	backoff := 5 * time.Second
	maxBackoff := 60 * time.Second
	for {
		ts := fmt.Sprintf("%d", time.Now().Unix())
		message := []byte(zid + ts)
		sig, err := core.Sign(message, edPriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Sign message: %v\n", err)
			time.Sleep(backoff)
			continue
		}

		type receiveRequest struct {
			ID  string `json:"id"`
			TS  string `json:"ts"`
			Sig string `json:"sig"`
		}
		reqData := receiveRequest{ID: zid, TS: ts, Sig: sig}
		data, err := json.Marshal(reqData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Marshal request: %v\n", err)
			time.Sleep(backoff)
			continue
		}

		req, err := http.NewRequest("POST", serverURL+"/receive", bytes.NewReader(data))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Create request: %v\n", err)
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fetch dispatches: %v\n", err)
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNoContent {
			backoff = 5 * time.Second
			time.Sleep(backoff)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "Server error: %s\n", string(body))
			time.Sleep(backoff)
			continue
		}

		var disps []core.Dispatch
		if err := json.NewDecoder(resp.Body).Decode(&disps); err != nil {
			fmt.Fprintf(os.Stderr, "Decode dispatches: %v\n", err)
			time.Sleep(backoff)
			continue
		}

		dispatches, err := LoadDispatches(zid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
			continue
		}

		for _, disp := range disps {
			fmt.Printf("Received dispatch from %s at %d\n", disp.From, disp.Timestamp)
			keys, err := fetchPublicKeys(disp.From)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Fetch sender keys: %v\n", err)
				continue
			}

			pubKey, err := base64.StdEncoding.DecodeString(keys.EdPub)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Decode public key: %v\n", err)
				continue
			}

			hashInput := fmt.Sprintf("%s%s%s%s%s%d%s%s", disp.From, strings.Join(append(disp.To, disp.CC...), ","), disp.Subject, disp.Body, disp.Nonce, disp.Timestamp, disp.ConversationID, disp.EphemeralPubKey)
			digest := sha256.Sum256([]byte(hashInput))
			valid, err := core.VerifySignature(pubKey, digest[:], disp.Signature)
			if err != nil || !valid {
				fmt.Fprintf(os.Stderr, "Invalid signature from %s: %v\n", disp.From, err)
				continue
			}

			ephemeralPub, err := base64.StdEncoding.DecodeString(disp.EphemeralPubKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Decode ephemeral key: %v\n", err)
				continue
			}
			var ephemeralPubKey [32]byte
			copy(ephemeralPubKey[:], ephemeralPub)

			sharedKey, err := core.DeriveSharedSecret(ecdhPriv, ephemeralPubKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Derive shared key: %v\n", err)
				continue
			}

			body, err := disp.DecryptBody(sharedKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Decrypt dispatch: %v\n", err)
				continue
			}
			disp.Body = body

			if err := StoreDispatch(zid, disp); err != nil {
				fmt.Fprintf(os.Stderr, "Store dispatch: %v\n", err)
				continue
			}
			if err := StoreBasket(zid, "inbox", disp.UUID); err != nil {
				fmt.Fprintf(os.Stderr, "Store inbox: %v\n", err)
				continue
			}

			// Get next SeqNo
			convs, err := LoadConversations(zid)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Load conversations: %v\n", err)
				continue
			}
			seqNo := 1
			for _, conv := range convs {
				if conv.ConID == disp.ConversationID {
					for _, entry := range conv.Dispatches {
						if entry.SeqNo >= seqNo {
							seqNo = entry.SeqNo + 1
						}
					}
				}
			}
			if err := StoreConversation(zid, disp.ConversationID, disp.UUID, seqNo); err != nil {
				fmt.Fprintf(os.Stderr, "Store conversation: %v\n", err)
				continue
			}

			// Check unanswered
			unanswered, err := LoadBasket(zid, "unanswered")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Load unanswered: %v\n", err)
				continue
			}
			for _, unansweredID := range unanswered {
				for _, unansweredDisp := range dispatches {
					if unansweredDisp.UUID == unansweredID && unansweredDisp.ConversationID == disp.ConversationID && unansweredDisp.To[0] == disp.From {
						if err := RemoveMessage(zid, "unanswered", unansweredID); err != nil {
							fmt.Fprintf(os.Stderr, "Remove unanswered: %v\n", err)
						}
						fmt.Printf("Removed dispatch %s from unanswered\n", unansweredID)
					}
				}
			}
		}

		backoff = 5 * time.Second
		time.Sleep(backoff)
	}
}

func confirmDelivery(zid string, dispID string, edPriv ed25519.PrivateKey) error {
	dispatches, err := LoadDispatches(zid)
	if err != nil {
		return fmt.Errorf("load dispatches: %w", err)
	}
	var disp core.Dispatch
	for _, d := range dispatches {
		if d.UUID == dispID {
			disp = d
			break
		}
	}

	type confirmRequest struct {
		ID        string `json:"id"`
		Timestamp int64  `json:"timestamp"`
		ConvID    string `json:"conversationID"`
		Sig       string `json:"sig"`
	}
	message := []byte(fmt.Sprintf("%s%d%s", zid, disp.Timestamp, disp.ConversationID))
	sig, err := core.Sign(message, edPriv)
	if err != nil {
		return fmt.Errorf("sign confirm: %w", err)
	}

	reqData := confirmRequest{
		ID:        zid,
		Timestamp: disp.Timestamp,
		ConvID:    disp.ConversationID,
		Sig:       sig,
	}
	data, err := json.Marshal(reqData)
	if err != nil {
		return fmt.Errorf("marshal confirm: %w", err)
	}

	req, err := http.NewRequest("POST", serverURL+"/confirm", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create confirm request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send confirm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("confirm failed: %s", string(body))
	}

	return nil
}

func pollDelivery(zid string, edPriv ed25519.PrivateKey) {
	for {
		dispIDs, err := LoadBasket(zid, "out")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load outbox: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for _, dispID := range dispIDs {
			if err := confirmDelivery(zid, dispID, edPriv); err == nil {
				if err := MoveMessage(zid, "out", "unanswered", dispID); err != nil {
					fmt.Fprintf(os.Stderr, "Move to unanswered: %v\n", err)
				} else {
					fmt.Printf("Dispatch %s confirmed delivered\n", dispID)
				}
			}
		}

		time.Sleep(5 * time.Second)
	}
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// handleDispatchView displays a dispatch and prompts for actions.
func handleDispatchView(zid string, disp core.Dispatch, basket string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) bool {
    reader := bufio.NewReader(os.Stdin)
    fmt.Printf("From: %s\nSubject: %s\nBody: %s\n", disp.From, disp.Subject, disp.Body)
    fmt.Println("1. Answer")
    fmt.Println("2. Pending")
    fmt.Println("3. Exit")
    fmt.Print("Choose an option: ")

    choice, _ := reader.ReadString('\n')
    choice = strings.TrimSpace(choice)

    switch choice {
    case "1":
        fmt.Print("Reply body: ")
        body, _ := reader.ReadString('\n')
        body = strings.TrimSpace(body)

        keys, err := fetchPublicKeys(disp.From)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Fetch recipient keys: %v\n", err)
            return false
        }

        ecdhPub, err := base64.StdEncoding.DecodeString(keys.ECDHPub)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Decode ecdh key: %v\n", err)
            return false
        }
        var ecdhPubKey [32]byte
        copy(ecdhPubKey[:], ecdhPub)

        var ephemeralPriv [32]byte
        if _, err := rand.Read(ephemeralPriv[:]); err != nil {
            fmt.Fprintf(os.Stderr, "Generate ephemeral key: %v\n", err)
            return false
        }

        ephemeralPub, err := curve25519.X25519(ephemeralPriv[:], curve25519.Basepoint)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Generate ephemeral public key: %v\n", err)
            return false
        }

        var sharedKey [32]byte
        shared, err := curve25519.X25519(ephemeralPriv[:], ecdhPubKey[:])
        if err != nil {
            fmt.Fprintf(os.Stderr, "Derive shared key: %v\n", err)
            return false
        }
        copy(sharedKey[:], shared)

        dispReply, err := core.NewEncryptedDispatch(zid, []string{disp.From}, nil, nil, "Re: "+disp.Subject, body, disp.ConversationID, edPriv, sharedKey, ephemeralPub)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Create reply: %v\n", err)
            return false
        }

        if err := StoreDispatch(zid, *dispReply); err != nil {
            fmt.Fprintf(os.Stderr, "Store reply dispatch: %v\n", err)
            return false
        }
        if err := StoreBasket(zid, "out", dispReply.UUID); err != nil {
            fmt.Fprintf(os.Stderr, "Store reply out: %v\n", err)
            return false
        }

        convs, err := LoadConversations(zid)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Load conversations: %v\n", err)
            return false
        }
        seqNo := 1
        for _, conv := range convs {
            if conv.ConID == disp.ConversationID {
                for _, entry := range conv.Dispatches {
                    if entry.SeqNo >= seqNo {
                        seqNo = entry.SeqNo + 1
                    }
                }
            }
        }
        if err := StoreConversation(zid, dispReply.ConversationID, dispReply.UUID, seqNo); err != nil {
            fmt.Fprintf(os.Stderr, "Store reply conversation: %v\n", err)
            return false
        }

        data, err := json.Marshal(dispReply)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Marshal reply: %v\n", err)
            return false
        }

        resp, err := http.Post(serverURL+"/send", "application/json", bytes.NewReader(data))
        if err != nil {
            fmt.Fprintf(os.Stderr, "Send reply: %v\n", err)
            return false
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
            body, _ := io.ReadAll(resp.Body)
            fmt.Fprintf(os.Stderr, "Send reply failed: %s\n", string(body))
            return false
        }

        if err := RemoveMessage(zid, basket, disp.UUID); err != nil {
            fmt.Fprintf(os.Stderr, "Remove original: %v\n", err)
            return false
        }

        fmt.Printf("Reply sent to %s\n", disp.From)
        return true

    case "2":
        if basket != "pending" {
            if err := MoveMessage(zid, basket, "pending", disp.UUID); err != nil {
                fmt.Fprintf(os.Stderr, "Move to pending: %v\n", err)
                return false
            }
            fmt.Println("Dispatch moved to pending")
            return true
        }
        return false

    case "3":
        return false

    default:
        fmt.Println("Invalid option")
        return false
    }
}

func main() {
    zid := flag.String("zid", "", "ZID for this client")
    flag.Parse()
    if *zid == "" {
        var err error
        *zid, err = promptNewOrLogin()
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to get ZID: %v\n", err)
            os.Exit(1)
        }
    }

    // Load keys
    is, err := LoadIdentity(filepath.Join("data", "identities", fmt.Sprintf("identity_%s.json", *zid)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load identity: %v\n", err)
		os.Exit(1)
	}
	if is.identity == nil {
		fmt.Fprintf(os.Stderr, "Identity for %s not found\n", *zid)
		os.Exit(1)
	}
	identity := is.identity

	edPriv, err := base64.StdEncoding.DecodeString(identity.EdPriv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decode ed private key: %v\n", err)
		os.Exit(1)
	}

	ecdhPrivBytes, err := base64.StdEncoding.DecodeString(identity.ECDHPriv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decode ecdh private key: %v\n", err)
		os.Exit(1)
	}
	var ecdhPriv [32]byte
	copy(ecdhPriv[:], ecdhPrivBytes)

    go checkForMessages(*zid, edPriv, ecdhPriv)
    go pollDelivery(*zid, edPriv)

    reader := bufio.NewReader(os.Stdin)
    for {
        fmt.Println("\n1. Send Dispatch")
        fmt.Println("2. View Inbox")
        fmt.Println("3. View Pending")
        fmt.Println("4. View Unanswered")
        fmt.Println("5. View Conversations")
        fmt.Println("6. Exit")
        fmt.Print("Choose an option: ")

        choice, _ := reader.ReadString('\n')
        choice = strings.TrimSpace(choice)

        switch choice {
        case "1":
            fmt.Print("To: ")
            to, _ := reader.ReadString('\n')
            to = strings.TrimSpace(to)
            fmt.Print("Subject: ")
            subject, _ := reader.ReadString('\n')
            subject = strings.TrimSpace(subject)
            fmt.Print("Body: ")
            body, _ := reader.ReadString('\n')
            body = strings.TrimSpace(body)

            keys, err := fetchPublicKeys(to)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Fetch recipient keys: %v\n", err)
                continue
            }

            ecdhPub, err := base64.StdEncoding.DecodeString(keys.ECDHPub)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Decode recipient ecdh key: %v\n", err)
                continue
            }
            var ecdhPubKey [32]byte
            copy(ecdhPubKey[:], ecdhPub)

            var ephemeralPriv [32]byte
            if _, err := rand.Read(ephemeralPriv[:]); err != nil {
                fmt.Fprintf(os.Stderr, "Generate ephemeral key: %v\n", err)
                continue
            }

            ephemeralPub, err := curve25519.X25519(ephemeralPriv[:], curve25519.Basepoint)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Generate ephemeral public key: %v\n", err)
                continue
            }

            var sharedKey [32]byte
            shared, err := curve25519.X25519(ephemeralPriv[:], ecdhPubKey[:])
            if err != nil {
                fmt.Fprintf(os.Stderr, "Derive shared key: %v\n", err)
                continue
            }
            copy(sharedKey[:], shared)

            disp, err := core.NewEncryptedDispatch(*zid, []string{to}, nil, nil, subject, body, "", edPriv, sharedKey, ephemeralPub)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Create dispatch: %v\n", err)
                continue
            }

            if err := StoreDispatch(*zid, *disp); err != nil {
                fmt.Fprintf(os.Stderr, "Store dispatch: %v\n", err)
                continue
            }
            if err := StoreBasket(*zid, "out", disp.UUID); err != nil {
                fmt.Fprintf(os.Stderr, "Store out: %v\n", err)
                continue
            }
            if err := StoreConversation(*zid, disp.ConversationID, disp.UUID, 1); err != nil {
                fmt.Fprintf(os.Stderr, "Store conversation: %v\n", err)
                continue
            }

            data, err := json.Marshal(disp)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Marshal dispatch: %v\n", err)
                continue
            }

            resp, err := http.Post(serverURL+"/send", "application/json", bytes.NewReader(data))
            if err != nil {
                fmt.Fprintf(os.Stderr, "Send dispatch: %v\n", err)
                continue
            }
            defer resp.Body.Close()

            if resp.StatusCode != http.StatusOK {
                body, _ := io.ReadAll(resp.Body)
                fmt.Fprintf(os.Stderr, "Send dispatch failed: %s\n", string(body))
                continue
            }

            fmt.Printf("Dispatch sent to %s\n", to)

        case "2":
            dispIDs, err := LoadBasket(*zid, "inbox")
            if err != nil {
                fmt.Fprintf(os.Stderr, "Load inbox: %v\n", err)
                continue
            }
            if len(dispIDs) == 0 {
                fmt.Println("Inbox is empty")
                continue
            }

            dispatches, err := LoadDispatches(*zid)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
                continue
            }

            for i, dispID := range dispIDs {
                for _, disp := range dispatches {
                    if disp.UUID == dispID {
                        fmt.Printf("%d. From: %s, Subject: %s\n", i+1, disp.From, disp.Subject)
                    }
                }
            }

            fmt.Print("Select dispatch number (or 0 to exit): ")
            var num int
            fmt.Scanln(&num)
            if num == 0 {
                continue
            }
            if num < 1 || num > len(dispIDs) {
                fmt.Println("Invalid selection")
                continue
            }

            var selected core.Dispatch
            for _, disp := range dispatches {
                if disp.UUID == dispIDs[num-1] {
                    selected = disp
                    break
                }
            }

            if handleDispatchView(*zid, selected, "inbox", edPriv, ecdhPriv) {
                fmt.Println("Dispatch processed")
            }

        case "3":
            dispIDs, err := LoadBasket(*zid, "pending")
            if err != nil {
                fmt.Fprintf(os.Stderr, "Load pending: %v\n", err)
                continue
            }
            if len(dispIDs) == 0 {
                fmt.Println("Pending is empty")
                continue
            }

            dispatches, err := LoadDispatches(*zid)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
                continue
            }

            for i, dispID := range dispIDs {
                for _, disp := range dispatches {
                    if disp.UUID == dispID {
                        fmt.Printf("%d. From: %s, Subject: %s\n", i+1, disp.From, disp.Subject)
                    }
                }
            }

            fmt.Print("Select dispatch number (or 0 to exit): ")
            var num int
            fmt.Scanln(&num)
            if num == 0 {
                continue
            }
            if num < 1 || num > len(dispIDs) {
                fmt.Println("Invalid selection")
                continue
            }

            var selected core.Dispatch
            for _, disp := range dispatches {
                if disp.UUID == dispIDs[num-1] {
                    selected = disp
                    break
                }
            }

            if handleDispatchView(*zid, selected, "pending", edPriv, ecdhPriv) {
                fmt.Println("Dispatch processed")
            }

        case "4":
            dispIDs, err := LoadBasket(*zid, "unanswered")
            if err != nil {
                fmt.Fprintf(os.Stderr, "Load unanswered: %v\n", err)
                continue
            }
            if len(dispIDs) == 0 {
                fmt.Println("No unanswered dispatches")
                continue
            }

            dispatches, err := LoadDispatches(*zid)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
                continue
            }

            for i, dispID := range dispIDs {
                for _, disp := range dispatches {
                    if disp.UUID == dispID {
                        fmt.Printf("%d. To: %s, Subject: %s\n", i+1, disp.To[0], disp.Subject)
                    }
                }
            }

            fmt.Print("Select dispatch number (0 to exit, -N to forget): ")
            var num int
            fmt.Scanln(&num)
            if num == 0 {
                continue
            }
            if num < 0 {
                num = -num
                if num < 1 || num > len(dispIDs) {
                    fmt.Println("Invalid selection")
                    continue
                }
                dispID := dispIDs[num-1]
                if err := RemoveMessage(*zid, "unanswered", dispID); err != nil {
                    fmt.Fprintf(os.Stderr, "Forget dispatch: %v\n", err)
                    continue
                }
                fmt.Printf("Dispatch %s forgotten\n", dispID)
                continue
            }
            if num < 1 || num > len(dispIDs) {
                fmt.Println("Invalid selection")
                continue
            }

            var selected core.Dispatch
            for _, disp := range dispatches {
                if disp.UUID == dispIDs[num-1] {
                    selected = disp
                    break
                }
            }

            fmt.Printf("To: %s\nSubject: %s\nBody: %s\n", selected.To[0], selected.Subject, selected.Body)
            fmt.Print("Press Enter to continue...")
            reader.ReadString('\n')

        case "5":
            convs, err := LoadConversations(*zid)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Load conversations: %v\n", err)
                continue
            }
            if len(convs) == 0 {
                fmt.Println("No conversations")
                continue
            }

            dispatches, err := LoadDispatches(*zid)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
                continue
            }

            for _, conv := range convs {
                fmt.Printf("\nConversation ID: %s\n", conv.ConID)
                entries := conv.Dispatches
                sort.Slice(entries, func(i, j int) bool {
                    return entries[i].SeqNo < entries[j].SeqNo
                })
                for _, entry := range entries {
                    for _, disp := range dispatches {
                        if disp.UUID == entry.DispID {
                            fmt.Printf("  %d. From: %s, Subject: %s, Time: %s\n", entry.SeqNo, disp.From, disp.Subject, time.Unix(disp.Timestamp, 0).Format(time.RFC3339))
                        }
                    }
                }
            }

            fmt.Print("Select conversation ID (or empty to exit): ")
            convID, _ := reader.ReadString('\n')
            convID = strings.TrimSpace(convID)
            if convID == "" {
                continue
            }

            var selectedConv struct {
                ConID      string
                Dispatches []struct {
                    DispID string
                    SeqNo  int
                }
            }
            for _, conv := range convs {
                if conv.ConID == convID {
                    selectedConv = conv
                    break
                }
            }
            if len(selectedConv.Dispatches) == 0 {
                fmt.Println("Conversation not found")
                continue
            }

            fmt.Println("\nConversation Thread:")
            for _, entry := range selectedConv.Dispatches {
                for _, disp := range dispatches {
                    if disp.UUID == entry.DispID {
                        fmt.Printf("  %d. From: %s, Subject: %s, Time: %s\n", entry.SeqNo, disp.From, disp.Subject, time.Unix(disp.Timestamp, 0).Format(time.RFC3339))
                    }
                }
            }
            fmt.Print("Press Enter to continue...")
            reader.ReadString('\n')

        case "6":
            os.Exit(0)

        default:
            fmt.Println("Invalid option")
        }
    }
}