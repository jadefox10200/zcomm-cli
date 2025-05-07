#!/bin/bash

# Create certs directory if it doesn't exist
mkdir -p data/certs

# Generate a private key
openssl genrsa -out data/certs/server.key 2048

# Create a certificate signing request (CSR)
openssl req -new -key data/certs/server.key -out data/certs/server.csr -subj "/CN=localhost"

# Generate a self-signed certificate valid for 365 days
openssl x509 -req -days 365 -in data/certs/server.csr -signkey data/certs/server.key -out data/certs/server.crt

# Clean up CSR
rm data/certs/server.csr

echo "Certificates generated in data/certs/"