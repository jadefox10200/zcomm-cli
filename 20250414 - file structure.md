server/
│
├── main.go              # Starts the server and routes handlers
├── handlers/
│   ├── messaging.go     # handleSend and handleReceive
│   ├── identity.go      # handleIdentity and IdentityStore logic
│   └── keys.go          # handlePublishKeys and handleFetchKeys
├── storage/
│   ├── inbox.go         # Inbox storage map and related logic
│   └── keys.go          # Public key directory + load/save logic
