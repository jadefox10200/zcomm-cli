# Zcomm Workflow and Encryption Model

## Overview
Zcomm is a secure messaging system built in Go 1.24, enabling users to send encrypted dispatches between identities (ZIDs, e.g., `z466453767`). It uses a client-server architecture with two servers storing public keys in `data/identities.json` and `data/pubkeys.json`. The system supports baskets (e.g., `IN`, `SENT`) for organizing messages and multiple hats (though not fully utilized here). Encryption ensures authenticity (via Ed25519 signatures) and confidentiality (via ECDH-derived AES-GCM encryption).

## Encryption Model
Zcomm employs a hybrid encryption model:
- **Ed25519 Signatures**:
  - Each identity has an Ed25519 key pair (`ed_priv`, `ed_pub`).
  - Used to sign dispatches and `/receive` requests, ensuring authenticity and integrity.
  - Stored as `verify_key` (client) and `ed_pub` (server).
- **ECDH Key Exchange**:
  - Each identity has a Curve25519 ECDH key pair (`ecdh_priv`, `ecdh_pub`).
  - Used to derive a shared secret for dispatch body encryption.
  - Stored as `exchange_key` (client) and `ecdh_pub` (server).
- **AES-GCM Encryption**:
  - Dispatch bodies are encrypted with AES-GCM using a shared key derived from ECDH.
  - Includes a nonce for security.
- **Ephemeral Keys**:
  - Each dispatch generates an ephemeral Curve25519 key pair.
  - Enhances forward secrecy by deriving a unique shared key per message.

## Workflow
The workflow involves identity creation, registration, sending dispatches, and receiving messages, with encryption at each step.

### 1. Identity Creation (Client)
- **Action**: User runs the client (`cmd/client/main.go`) and selects `C` to create a new ZID.
- **Process**:
  - Generate Ed25519 key pair (`ed_priv`, `ed_pub`).
  - Generate Curve25519 ECDH key pair (`ecdh_priv`, `ecdh_pub`).
  - Save to `data/identities/identity_<zid>.json` (e.g., `identity_z466453767.json`):
    ```json
    {
      "id": "z466453767",
      "ed_priv": "...",
      "ed_pub": "...",
      "ecdh_priv": "...",
      "ecdh_pub": "..."
    }
    ```
  - Example: `cmd/client/identity.go:GenerateAndStoreNewIdentity`.
- **Encryption**: None (keys are generated locally).

### 2. Identity Registration (Client to Server)
- **Action**: Client posts identity to server’s `/identity` endpoint.
- **Process**:
  - Client sends:
    ```json
    {
      "id": "z466453767",
      "verify_key": "<ed_pub>",
      "exchange_key": "<ecdh_pub>"
    }
    ```
  - Server (`cmd/server/handlers.go:HandleIdentity`):
    - Stores in `data/identities.json` (via `IdentityStore`).
    - Copies to `data/pubkeys.json` (via `KeyStore`):
      ```json
      {
        "z466453767": {
          "id": "z466453767",
          "ed_pub": "<ed_pub>",
          "ecdh_pub": "<ecdh_pub>"
        }
      }
      ```
  - Example: `cmd/server/identity_store.go`, `cmd/server/keys.go`.
- **Encryption**: None (public keys only).

### 3. Sending a Dispatch (Client to Server)
- **Action**: User selects `1` to send a dispatch to another ZID (e.g., `z632724224`).
- **Process**:
  - Client (`cmd/client/main.go:294-351`):
    - Fetches recipient’s public keys from `/pubkey?id=<toID>`.
    - Generates ephemeral Curve25519 key pair (`ephemeral_priv`, `ephemeral_pub`).
    - Derives shared key using ECDH: `sharedKey = DeriveSharedSecret(ephemeral_priv, recipient.ecdh_pub)`.
    - Encrypts body with AES-GCM: `encryptedBody = AES-GCM(sharedKey, body, nonce)`.
    - Signs dispatch (`core/dispatch.go:NewEncryptedDispatch`):
      - Hash: `SHA256(from + to + cc + subject + body + nonce + timestamp + conversationID + ephemeralPubKey)`.
      - Signature: `ed25519.Sign(ed_priv, hash)`.
    - Posts to `/send`:
      ```json
      {
        "from": "z466453767",
        "to": ["z632724224"],
        "subject": "Test",
        "body": "<encrypted>",
        "nonce": "...",
        "timestamp": 1623456789,
        "conversationID": "...",
        "ephemeralPubKey": "<ephemeral_pub>",
        "signature": "<signature>"
      }
      ```
  - Server (`cmd/server/handlers.go:HandleSend`):
    - Verifies recipient exists in `KeyStore`.
    - Stores dispatch in `Inbox.inbox[toID]`.
  - Client stores in `z466453767/sent.json`.
- **Encryption**:
  - Body: AES-GCM with ECDH-derived key.
  - Signature: Ed25519 on dispatch hash.

### 4. Receiving Dispatches (Client to Server)
- **Action**: Client polls `/receive` to fetch dispatches.
- **Process**:
  - Client (`cmd/client/main.go:checkForMessages`):
    - Signs request: `sig = ed25519.Sign(ed_priv, zid + ts)`.
    - Posts to `/receive`:
      ```json
      {
        "id": "z466453767",
        "ts": "1623456789",
        "sig": "<signature>"
      }
      ```
  - Server (`cmd/server/handlers.go:HandleReceive`):
    - Verifies signature: `ed25519.Verify(ed_pub, id + ts, sig)`.
    - Returns dispatches from `Inbox.inbox[id]`.
  - Client:
    - Fetches sender’s `ed_pub` from `/pubkey`.
    - Verifies dispatch signature: `ed25519.Verify(sender.ed_pub, dispatch.hash, signature)`.
    - Derives shared key: `sharedKey = DeriveSharedSecret(ecdh_priv, dispatch.ephemeralPubKey)`.
    - Decrypts body: `body = AES-GCM-Decrypt(sharedKey, encryptedBody, nonce)`.
    - Stores in `z466453767/inbox.json`.
- **Encryption**:
  - Request: Ed25519 signature.
  - Dispatch body: AES-GCM decryption.
  - Dispatch signature: Ed25519 verification.

### 5. Storage and Organization
- **Client**:
  - Keys: `data/identities/identity_<zid>.json`.
  - Dispatches: `<zid>/inbox.json`, `<zid>/sent.json`.
  - Conversations: `<zid>/conversations.json` (maps conversation IDs to dispatch IDs).
- **Server**:
  - Keys: `data/identities.json`, `data/pubkeys.json` (redundant, stores `id`, `ed_pub`, `ecdh_pub`).
  - Dispatches: In-memory `Inbox.inbox` (cleared after delivery).
- **Baskets**:
  - `IN`: Received dispatches.
  - `SENT`: Sent dispatches.
  - Supports extensibility for custom baskets.

## Security Features
- **Authentication**: Ed25519 signatures ensure sender identity and message integrity.
- **Confidentiality**: AES-GCM encrypts dispatch bodies, accessible only to intended recipients.
- **Forward Secrecy**: Ephemeral ECDH keys per dispatch prevent past message decryption if keys are compromised.
- **Non-repudiation**: Signatures prevent senders from denying messages.
- **Duplicate Prevention**: Server checks for existing identities during registration.

## Workflow Diagram
Below is a Mermaid sequence diagram illustrating the workflow for sending and receiving a dispatch between `z466453767` (Alice) and `z632724224` (Bob).

```mermaid
sequenceDiagram
    participant A as Alice (z466453767)
    participant S as Server
    participant B as Bob (z632724224)

    %% Identity Registration
    A->>S: POST /identity {id, verify_key, exchange_key}
    S-->>A: 200 OK
    B->>S: POST /identity {id, verify_key, exchange_key}
    S-->>B: 200 OK

    %% Sending Dispatch
    A->>S: GET /pubkey?id=z632724224
    S-->>A: {ed_pub, ecdh_pub}
    Note over A: Generate ephemeral key pair
    Note over A: Derive shared key with Bob's ecdh_pub
    Note over A: Encrypt body with AES-GCM
    Note over A: Sign dispatch with ed_priv
    A->>S: POST /send {from, to, encrypted_body, signature, ...}
    S-->>A: 200 OK
    Note over S: Store dispatch in inbox[z632724224]

    %% Receiving Dispatch
    B->>S: POST /receive {id, ts, sig}
    Note over S: Verify signature with ed_pub
    S-->>B: [{from, encrypted_body, signature, ...}]
    Note over B: Fetch Alice's ed_pub
    Note over B: Verify dispatch signature
    Note over B: Derive shared key with ephemeralPubKey
    Note over B: Decrypt body with AES-GCM
    Note over B: Store in inbox.json
```

## Notes
- **Redundancy**: The server stores keys in both `identities.json` and `pubkeys.json` for design separation (registration vs. lookup), though this is redundant.
- **Baskets and Hats**: Baskets organize messages; multiple hats are supported but unused in this workflow.
- **Error Handling**: Clients retry on network errors; servers validate inputs and signatures.
- **Dependencies**: Uses `crypto/ed25519`, `golang.org/x/crypto/curve25519`, and `crypto/sha256`.

This document and diagram summarize Zcomm’s secure messaging workflow, tested as of April 16, 2025.