#!/bin/bash

# --- 1) Check if Rust (rustc + cargo) is installed ---
if ! command -v rustc > /dev/null 2>&1 || ! command -v cargo > /dev/null 2>&1; then
  echo "Error: Rust (rustc) and/or Cargo not found on your system."
  echo "Please install Rust from: https://www.rust-lang.org/tools/install"
  exit 1
fi

# Prompt for server IP address
read -p "Enter server IP address: " SERVER_IP

# Create a directory for keys/certs
mkdir -p keys

echo "Generating CA certificate..."

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout keys/ca-key.pem \
  -out keys/ca-cert.pem \
  -subj "/CN=Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "Generating server key..."

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out keys/server-key.pem

echo "Generating server CSR..."

openssl req -new \
  -key keys/server-key.pem \
  -out keys/server.csr \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:${SERVER_IP}"


cat > keys/server-ext.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:${SERVER_IP}
EOF

echo "Signing the server certificate..."

openssl x509 -req -sha256 \
  -in keys/server.csr \
  -CA keys/ca-cert.pem \
  -CAkey keys/ca-key.pem \
  -CAcreateserial \
  -out keys/server-cert.pem \
  -days 365 \
  -extfile keys/server-ext.cnf \
  -copy_extensions copy

# Copy the CA cert into the current directory
cp keys/ca-cert.pem ./ca-cert.pem

echo "Adjusting config.toml..."
# 5) Update or append server_address and server_sni lines in config.toml
if [[ -f config.toml ]]; then
  if grep -q '^server_address\s*=' config.toml; then
    sed -i "s|^server_address\s*=.*|server_address = \"${SERVER_IP}:8443\"|" config.toml
  else
    echo "server_address = \"${SERVER_IP}:8443\"" >> config.toml
  fi

  if grep -q '^server_sni\s*=' config.toml; then
    sed -i "s|^server_sni\s*=.*|server_sni = \"${SERVER_IP}\"|" config.toml
  else
    echo "server_sni = \"${SERVER_IP}\"" >> config.toml
  fi

  echo "config.toml updated with new IP: ${SERVER_IP}"
else
  echo "Warning: config.toml not found in current directory; skipping."
fi

# 6) Build the project in release mode
echo "Building project in release mode..."
cargo build --release

# 7) Copy the resulting binaries to the current working directory
echo "Copying release binaries to the current directory..."
cp target/release/{client,server} . 2>/dev/null || echo "No binaries found in target/release/ (or copy failed)."

echo "Done! All keys/certs are in 'keys/'. 'ca-cert.pem' also copied to current directory."
echo "Any release binaries have been copied to the current directory."

