# Forge - Network Tunneling & SOCKS Proxy Tool

Forge is a powerful network tunneling tool written in Rust that provides secure TCP and UDP tunneling with SOCKS5 proxy capabilities and TLS-encrypted command channels. Deploy clients on remote networks and route traffic through them from your local machine.

## Features

- **SOCKS5 Proxy**: Route traffic through remote clients using standard SOCKS5 protocol
- **Dynamic Tunnel Management**: Create, modify, and close TCP/UDP tunnels on-the-fly
- **Multi-Architecture Support**: Cross-compile for MIPS, PowerPC, ARM, and x86_64
- **Enhanced CLI**: Full readline support with command history and navigation
- **Secure Command Channel**: TLS-encrypted control channel between server and clients
- **Network Routing**: Access internal networks through deployed clients
- **Live Reconfiguration**: Modify endpoints without restarting connections

## Architecture

```
[Laptop/Server]          [Client on Router/Pi]          [Target Network]
    192.168.1.10              192.168.50.1                 192.168.50.0/24
         |                         |                            |
    Server :8443 <---TLS--->  Client :8443                      |
         |                         |                            |
  nmap --proxies            SOCKS5 Proxy :1080                  |
  socks5://50.1:1080               |                            |
         |                         |                            |
         +-------------------------+-------------------------->Target
```

## Quick Start

### 1. Setup and Build

**First-time setup (certificates + configuration + build):**

```bash
git clone <repository>
cd forge

# Complete setup: generates certificates, updates config, builds binaries
./build-forge.sh
# This will prompt for your server IP address
```

**Cross-compile for multiple architectures:**

```bash
# Install targets first
rustup target add aarch64-unknown-linux-gnu mipsel-unknown-linux-musl armv7-unknown-linux-gnueabihf

# Build client for all architectures
./build-all.sh
```

**Manual build (current architecture only):**

```bash
cargo build --release
```

### 2. Deploy Server (Control Point)

```bash
# Start server on your laptop/control machine
./target/release/server --addr 0.0.0.0:8443 --cert keys/server-cert.pem --key keys/server-key.pem
```

### 3. Deploy Client (Remote Network)

```bash
# Copy client binary to router/Pi/remote machine
scp target/release/client user@router:/tmp/

# On remote machine, simply run (config is baked in)
./client
```

**Note:** Client configuration (server IP, certificates) is compiled into the binary during build.

### 4. Start SOCKS Proxy

```bash
# On server console
forge> clients                    # List connected clients
forge> socks client123 start 1080 30  # Start SOCKS5 proxy on port 1080 (30s timeout)
```

### 5. Use SOCKS Proxy

```bash
# From your laptop, scan remote network through client
nmap --proxies socks4://ROUTER_IP:1080 192.168.50.0/24 --open

# For tools that support SOCKS5
curl --socks5 ROUTER_IP:1080 http://192.168.50.100/
ssh -o ProxyCommand="nc -X 5 -x ROUTER_IP:1080 %h %p" user@192.168.50.50

# Or use proxychains for universal SOCKS5 support
proxychains4 nmap 192.168.50.0/24 --open
```

## Cross-Platform Compilation

Build client for multiple architectures:

```bash
# Install targets
rustup target add aarch64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-musl
rustup target add mipsel-unknown-linux-musl
rustup target add armv5te-unknown-linux-musleabi
rustup target add armv7-unknown-linux-gnueabihf

# Build for specific architecture
cargo build --release --bin client --target aarch64-unknown-linux-gnu

# Build for all architectures
./build-all.sh
```

**Supported Architectures:**

- x86_64-unknown-linux-gnu (Intel/AMD 64-bit)
- aarch64-unknown-linux-gnu (ARM 64-bit - Pi 4, modern routers)
- aarch64-unknown-linux-musl (ARM 64-bit static)
- armv7-unknown-linux-gnueabihf (ARM 32-bit hard-float - Pi 3)
- armv5te-unknown-linux-musleabi (ARM v5 - older devices)
- mipsel-unknown-linux-musl (MIPS Little Endian - routers)
- mips-unknown-linux-musl (MIPS Big Endian)
- powerpc64-unknown-linux-gnu (PowerPC 64-bit)
- powerpc-unknown-linux-gnu (PowerPC 32-bit)

## Server Commands

Enhanced CLI with full readline support (arrows, history, tab completion):

```bash
forge> help                              # Show all commands
forge> clients                           # List connected clients
forge> tunnels <client_id>               # List client's tunnels
forge> create <client_id> <local_port> <target_host> <target_port> [tcp|udp] # Create tunnel
forge> socks <client_id> start <port> [timeout_seconds]  # Start SOCKS5 proxy
forge> socks <client_id> stop            # Stop SOCKS5 proxy
forge> close <client_id> <local_port>    # Close tunnel
forge> exit                              # Shutdown server
```

## Use Cases

### Network Reconnaissance

```bash
# Deploy client on DMZ machine, scan internal network
forge> socks dmz-client start 1080 30
nmap --proxies socks4://dmz-ip:1080 10.0.0.0/24 --open
```

### Access Internal Services

```bash
# TCP tunnel for web services
forge> create client1 8080 192.168.1.1 80 tcp
curl http://localhost:8080

# UDP tunnel for DNS queries
forge> create client1 5353 192.168.1.1 53 udp
dig @localhost -p 5353 example.com

# SOCKS5 proxy for general purpose
forge> socks edge-client start 1080 60
curl --socks5 edge-ip:1080 http://192.168.1.1/
```

### SSH Through Proxy

```bash
# SSH to machine only reachable through client
ssh -o ProxyCommand="nc -X 5 -x client-ip:1080 %h %p" user@internal-host
```

### Multi-Hop Networking

```bash
# Chain through multiple networks
Client A (Network 1) -> Client B (Network 2) -> Target (Network 3)
```

## Configuration

### Client Configuration (Compile-Time)

Client configuration is defined in `config.toml` and compiled into the binary:

```toml
server_address = "YOUR_SERVER_IP:8443"
server_sni = "YOUR_SERVER_IP" 
ca_cert = "ca-cert.pem"  # Certificate is embedded in binary
```

After running `./build-forge.sh` or `cargo build`, the client binary contains all necessary configuration and certificates.

### Server Arguments

- `--addr`: Listen address (default: 0.0.0.0:8443)
- `--cert`: Server certificate path
- `--key`: Server private key path
- `--port-range`: Allowed tunnel ports (default: 1024-65535)

## Security Considerations

- **TLS Encryption**: All control traffic is encrypted
- **Certificate Validation**: Clients validate server certificates
- **Port Restrictions**: Configurable port ranges prevent privilege escalation
- **No Authentication**: Currently uses certificate-based trust only

## Protocol Support

- **TCP Tunnels**: Full bidirectional TCP tunneling support
- **UDP Tunnels**: Stateless UDP packet forwarding with response handling  
- **SOCKS5 Proxy**: Complete SOCKS5 implementation with TCP and basic UDP association

## Removed Features

Port scanning functionality has been removed to prevent triggering network security policies. Use external tools like nmap through the SOCKS proxy instead.

## Troubleshooting

### Certificate Issues

```bash
# Regenerate certificates
./build-forge.sh
```

### Network Issues

- Check firewall rules on both server and client
- Verify TLS connectivity: `openssl s_client -connect server:8443`
- Ensure client can reach server on port 8443

### SOCKS Proxy Issues

- Test connectivity: `curl --socks5 client-ip:1080 http://httpbin.org/ip`
- For nmap, use: `nmap --proxies socks4://client-ip:1080 target --open`
- For broader compatibility, use: `proxychains4 nmap target --open`
- Check client logs for connection errors
- Verify target network is reachable from client

## Development

### Project Structure

- `src/bin/server.rs` - Server with integrated SOCKS management
- `src/bin/client.rs` - Unified client with SOCKS capability  
- `src/socks.rs` - SOCKS5 proxy implementation
- `src/protocol.rs` - Command/response protocol
- `src/tunnel.rs` - TCP tunnel implementation

### Build Scripts

**`./build-forge.sh`** - Complete first-time setup:

- Prompts for server IP address
- Generates TLS certificates (CA, server cert/key)
- Updates `config.toml` with your server IP
- Builds binaries for current architecture
- Copies binaries and certificates to current directory

**`./build-all.sh`** - Cross-compilation for deployment:

- Builds client binary for multiple architectures
- Creates `target/client-{architecture}` files
- Requires targets to be installed first with `rustup target add`

**`cargo build --release`** - Standard Rust build:

- Builds server and client for current architecture only
- Outputs to `target/release/`

### Building from Source

```bash
# First time setup
./build-forge.sh

# Cross-compile clients
./build-all.sh

# Or manual build
cargo build --release --bin server --bin client
```

Clean, minimal codebase focused on core tunneling and SOCKS functionality.

