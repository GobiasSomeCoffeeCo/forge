# Forge - TCP Tunneling Tool (Work in Progress)

Forge is a TCP tunneling tool written in Rust that allows you to create tunnels between hosts with a TLS-encrypted command channel for secure tunnel management. The actual tunnel traffic is transported over direct (unsecured) TCP connections.

**Note:** This is an actively developed project. The current implementation includes detailed debug messages which, while verbose, are intentionally left in place to assist with development and troubleshooting during this phase.

## Features

- **TLS Encryption**: All tunnel traffic is encrypted using modern TLS protocols
- **Secure Command Channel**: Control messages are sent over a TLS-encrypted connection
- **Interactive Management**: Command-line interface for managing tunnels

## Prerequisites

- Rust 1.70 or later
- OpenSSL command-line tools (for certificate generation)

## Quick Start

1. Clone the repository and navigate to the project directory.

2. Run the setup script to generate certificates and build the project:
   ```bash
   ./build-forge.sh
   ```
   You will be prompted to enter the server's IP address.

3. Start the server:
   ```bash
   ./server --addr 0.0.0.0:8443 --key keys/server-key.pem --cert keys/server-cert.pem
   ```

4. In a separate terminal or on another machine, start the client:
   ```bash
   ./client
   ```

## Configuration

### Server Configuration

The server accepts the following command-line arguments:

- `--addr`: Address to listen on (default: "127.0.0.1:8443")
- `--key`: Path to server private key (PKCS8 PEM)
- `--cert`: Path to server certificate (PEM)
- `--allow-udp`: Allow UDP tunnels (default: TCP only) # Currently not implemented
- `--port-range`: Port range allowed for tunnels (default: "1024-65535")

### Client Configuration

Client configuration is stored in `config.toml`:

```toml
server_address = "192.168.1.4:8443"
server_sni = "192.168.1.4"
ca_cert = "ca-cert.pem"
```

## Server Commands

Once the server is running, you can use the following commands in the server's interactive console:

- `help`: Display available commands
- `clients`: List connected clients
- `tunnels <client_id>`: List tunnels for a specific client
- `create <client_id> <local_port> <target_host> <target_port>`: Create a new tunnel
- `modify <client_id> <local_port> <new_host> <new_port>`: Modify an existing tunnel
- `close <client_id> <local_port>`: Close a tunnel
- `exit`: Shut down the server

## Security

The project implements several security measures:

- TLS encryption for the command channel (server certificate verification)
- Configurable port ranges to restrict tunnel endpoints (default: 1024-65535)
- Client registration system for tunnel management

## Architecture

### Components

- **TunnelManager**: Handles creation and management of tunnels
- **MultiplexedTunnel**: Manages multiple logical connections over a single TLS connection
- **Protocol**: Defines the command and control protocol between client and server

### Message Types

- **OpenChannel**: Creates a new tunnel
- **CloseChannel**: Terminates an existing tunnel
- **Data**: Carries tunnel traffic
- **Command/Response**: Control messages for tunnel management

## Building from Source

1. Ensure you have Rust and Cargo installed
2. Clone the repository
3. Run `cargo build --release`
4. The binaries will be available in `target/release/`

## Limitations

- Currently supports TCP tunnels only (UDP support planned)
- No built-in authentication beyond TLS certificates
- TCP tunnels created are currently unencrypted


## Troubleshooting

### Common Issues

1. **Certificate Errors**
   - Ensure the CA certificate is properly configured
   - Verify the server's certificate matches its hostname/IP
   - Check certificate expiration dates

2. **Connection Issues**
   - Verify the server address and port are correct
   - Check firewall settings
   - Ensure the target service is running

3. **Permission Issues**
   - Ports below 1024 require root/administrator privileges
   - Check file permissions on certificates and keys

### Debug Logging

Both client and server provide detailed logging. Check the console output for error messages and connection details.










