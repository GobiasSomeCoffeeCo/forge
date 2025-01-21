#!/bin/bash

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout ca-key.pem \
  -out ca-cert.pem \
  -subj "/CN=Test CA" \
  -addext "basicConstraints=critical,CA:TRUE"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out server-key.pem

openssl req -new \
  -key server-key.pem \
  -out server.csr \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

cat > server-ext.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req \
  -in server.csr \
  -CA ca-cert.pem \
  -CAkey ca-key.pem \
  -CAcreateserial \
  -out server-cert.pem \
  -days 365 \
  -extfile server-ext.cnf
