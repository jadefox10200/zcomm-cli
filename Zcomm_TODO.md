# Zcomm ToDo List

Recommended Roadmap
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
