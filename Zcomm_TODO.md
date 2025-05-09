# Zcomm ToDo List


# Updated Zcomm Development Roadmap 3 May 2025:

This roadmap prioritizes features for Zcomm, aligning with its mission as a secure, action-oriented messaging platform. The email gateway is excluded due to complexity and security risks. Rotating keys and device sync are added for security and usability.

## Smith Notes:
- Implement "decline" as an option for dispatches. This will also send a notification of type deline. 
  This allows users to not answer a dispatch and simply decline to answer and informing the original 
  of the action so it is removed from unaswered. This is basically a non-verbal ack and will archive the 
  conversation. 
- Possibly need a discussion data model. Right now we have a conversation. When we add CC how do we handle someone
  who decides to answer a CC? This would start a new conversation but there is no link between the two even thos the
  dispatch will then appear in two conversations. We would need a discussion model. While this won't have an active/inactive
  status, we still should provide the ability to view a discussion and select any conversation. This way if we have an 
  entire team talking, we can view the discussion. If Joe is get CC from two conversations on the same discussion, he can 
  then view the discussion. Discussions don't have unique subjects. Since they can only start from a single conversation, every
  dispatch in a discussion will always match the conversation subjects no matter how many conversations start. This is simply something more on the back end to link up and track for when CC is implemented. 
- Remove the multiple To field. 

## Phase 1: Security and Core Usability (0-3 Months)
- **Login System for Key Security**
  - Encrypt private keys with password-derived keys (Argon2).
  - Add CLI login prompt, secure identity files.
  - *Why*: Protects keys, foundational for trust.
- **Rotating Keys**
  - Implement periodic ECDH and Ed25519 key rotation.
  - Update server public keys, re-encrypt local storage, add CLI commands.
  - *Why*: Enhances forward secrecy, critical for security.
- **Contacts and Aliases**
  - Implement contact database and alias mapping.
  - Add CLI commands for contact management, sync public keys.
  - *Why*: Simplifies addressing, enhances usability.
- **Task Creation Based on Dispatches**
  - Define task struct, update SQLite schema.
  - Add CLI commands for task creation, integrate with PENDING basket.
  - *Why*: Supports action-oriented workflows.

## Phase 2: Usability Enhancements (3-6 Months)
- **GUI Front-End**
  - Build web-based GUI (React) or Electron app.
  - Integrate with HTTP server, implement basket views.
  - *Why*: Improves accessibility, enables formal display.
- **Formal Letter Display for Dispatches**
  - Create HTML/CSS templates with headers and signatures.
  - Integrate into GUI for professional presentation.
  - *Why*: Enhances professionalism.

## Phase 3: Functional Enhancements (6-9 Months)
- **CC for Dispatches**
  - Extend `To` field for CC recipients, update encryption.
  - Add CLI/GUI support for CC.
  - *Why*: Supports transparency.
- **File Attachments**
  - Extend dispatch struct for encrypted files.
  - Add CLI/GUI upload/download, enforce size limits.
  - *Why*: Enables document sharing.
- **Device Sync**
  - Implement sync protocol for identity, dispatches, baskets, tasks.
  - Add conflict resolution, secure key storage, GUI integration.
  - *Why*: Enables multi-device support.

## Phase 4: Advanced Features (9-12 Months)
- **Memos for Group Communication**
  - Define memo struct, implement group key management.
  - Restrict dispatches to one primary recipient, update UI.
  - *Why*: Enables group announcements.
- **Forwarding Dispatches**
  - Implement dispatch referencing, re-encrypt forwarded content.
  - Add CLI/GUI forwarding options, preserve signatures.
  - *Why*: Supports collaboration.

## Phase 5: Experimental Features (12+ Months)
- **VIA Routing with Rejection**
  - Add VIA field, implement routing and rejection logic.
  - Create REJECTED basket, update CLI/GUI.
  - *Why*: Supports niche workflows.
-----------------------------------------------------------------------

4. Server-Side ZID-to-Account Mapping
Concept: Since Zcomm already registers ZIDs with the server (POST /identity), extend this to enforce one account per user by linking all ZIDs to a single account ID. The server rejects new account creation if the user’s ZIDs are already associated with another account.

Implementation:

Account ID:
Generate a unique account ID (e.g., UUID) during account creation and store it in data/accounts/account_<username>.json.
Send the account ID with ZID registration requests in GenerateAndStoreNewIdentity.
Server-Side Logic:
Modify the /identity endpoint to include an account_id field:
go

type serverIdentity struct {
    ID          string `json:"id"`
    AccountID   string `json:"account_id"`
    VerifyKey   string `json:"verify_key"`
    ExchangeKey string `json:"exchange_key"`
}
Store a mapping of ZIDs to account IDs in the server database:
sql

CREATE TABLE account_zids (zid TEXT PRIMARY KEY, account_id TEXT);
During account creation, check if any ZIDs are already linked to another account ID.
Enforcement:
If a user tries to create a new account and registers a ZID already tied to another account ID, reject the request.
Pros:

Leverages existing ZID registration infrastructure.
Transparent to users (no additional input like email).
Scalable for identity matching in future phases.
Cons:

Requires server-side database changes.
Users could create multiple accounts before registering ZIDs, unless account creation is also server-side.
Needs careful handling of account recovery (e.g., merging ZIDs).
Zcomm Considerations:

Ideal for Zcomm, as it builds on the existing /identity endpoint.
Store account IDs in identity_<zid>.json for consistency.
Add a server-side /account endpoint to register the account ID before ZID creation.

-----------------------------------------------------------------------


Recommended Roadmap

Updated Roadmap:
Database Implementation (5-7 days).
CC Implementation (2-3 days).
GUI Front-End (7-10 days, detailed below).
Security Enhancements (3-5 days).
User-Friendly Features (3-5 days).
Testing and Polish (5-7 days).
Total: 25-37 days (4-5 weeks).

---
CC Implementation (1-2 days):
Add CC to Dispatch, update client/server logic.
Test one-to-one and CC scenarios.
Storage Abstraction (2-3 days):
Introduce Storage interface, refactor to FileStorage.
Prepare for database without disrupting CC.
Security Enhancements (3-5 days):
Add key rotation, stronger validation, audit logging, TLS enforcement.
Ensure robust encryption and authentication.
Database Migration (5-10 days, when needed):
Migrate to SQLite or PostgreSQL when scale or queries demand it.
Use Storage interface to minimize code changes.
User Features (ongoing):
Add aliases, search, group messaging as user needs grow.

## 🔐 Identity & Key Management
- [ ] Create a secure `GenerateIdentity()` flow.
- [ ] Ensure local keyring storage is complete and encrypted.
- [ ] Implement server-side identity registration and validation.
- [ ] Design and enforce identity uniqueness and verification (e.g. signature-based trust model or external validation).
- [ ] Implement a secure way to sync identities across devices.

## 💬 Message Handling
- [x] Store incoming messages in appropriate baskets (IN, PENDING, OUT).
- [x] Implement basket viewing via `ViewBasket(basket string)`.
- [ ] Allow decrypt-on-view pattern for inbox messages using stored keyring.

## 🔄 Client-Server Protocols
- [ ] Implement signed ID registration with the server.
- [ ] Allow clients to retrieve peer public keys from server.
- [ ] Consider end-game design: will Zcomm stay relay-based or evolve into peer-to-peer?

## 📦 Storage & Local Features
- [x] Implement JSON-based local storage for all baskets.
- [x] Implement local keyring for known public keys.
- [ ] Consider encrypted local storage for keys/messages (later).
- [ ] Add conversation threading view support.
