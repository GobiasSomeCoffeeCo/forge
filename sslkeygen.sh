#!/bin/bash

# openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
#   -keyout ca-key.pem \
#   -out ca-cert.pem \
#   -subj "/CN=Test CA" \
#   -addext "basicConstraints=critical,CA:TRUE"

# openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
#   -out server-key.pem

# openssl req -new \
#   -key server-key.pem \
#   -out server.csr \
#   -subj "/CN=localhost" \
#   -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# cat > server-ext.cnf <<EOF
# basicConstraints=CA:FALSE
# keyUsage=digitalSignature,keyEncipherment
# extendedKeyUsage=serverAuth
# subjectAltName=DNS:localhost,IP:127.0.0.1
# EOF

# openssl x509 -req \
#   -in server.csr \
#   -CA ca-cert.pem \
#   -CAkey ca-key.pem \
#   -CAcreateserial \
#   -out server-cert.pem \
#   -days 365 \
#   -extfile server-ext.cnf


# Generate CA certificate
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
-keyout ca-key.pem \
-out ca-cert.pem \
-subj "/CN=Test CA" \
-addext "basicConstraints=critical,CA:TRUE" \
-addext "keyUsage=critical,keyCertSign,cRLSign"

# Generate server key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
-out server-key.pem

# Generate server CSR
openssl req -new \
-key server-key.pem \
-out server.csr \
-subj "/CN=localhost" \
-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Create extension file
cat > server-ext.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

# Sign server certificate with SHA-256
openssl x509 -req -sha256 \
-in server.csr \
-CA ca-cert.pem \
-CAkey ca-key.pem \
-CAcreateserial \
-out server-cert.pem \
-days 365 \
-extfile server-ext.cnf \
-copy_extensions copy