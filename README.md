# Zcomm

**Zcomm** is a decentralized, secure communication protocol designed for official, immutable messaging. Think of it as "Signal for business" — with cryptographic guarantees, no central storage, and total control for users.

### ✨ Features
- End-to-end encrypted messaging using AES + public/private keys
- Stateless server relay ("switchboard") for message routing
- Message chaining for immutability and auditability
- Device sync via encrypted bundles
- Open-source and privacy-first

---

### 📦 Components

- `zcomm-server/` – Go-based relay server (stateless)
- `zcomm-client/` – CLI or client-side message tooling (Go)
- `docs/` – Protocol spec and design docs
- `examples/` – Test conversations and message formats

---

### 🔐 Protocol Principles

- **Identity = Public Key**
- **No server-side message storage**
- **JSON-based encrypted messages**
- **Signed, verifiable message chains**
- **Exportable to signed PDFs for legal use**

---

### 📄 License

Zcomm is open-source under the [MIT License](LICENSE).
