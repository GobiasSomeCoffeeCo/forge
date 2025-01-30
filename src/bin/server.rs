// src/bin/server.rs
use anyhow::{Context, Result, anyhow};
use clap::Parser;
use forge::protocol::{Command, Response, TunnelDirection, TunnelInfo};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Parser)]
struct ServerArgs {
    /// Address to listen on, e.g. "0.0.0.0:8443"
    #[arg(long, default_value = "0.0.0.0:8443")]
    addr: String,

    /// Path to server private key (PKCS8 PEM)
    #[arg(long, default_value = "keys/server-key.pem")]
    key: PathBuf,

    /// Path to server certificate (PEM)
    #[arg(long, default_value = "keys/server-cert.pem")]
    cert: PathBuf,

    /// Allow UDP tunnels (default is TCP only)
    #[arg(long)]
    allow_udp: bool,

    /// Port range allowed for tunnels (e.g. "1024-65535")
    #[arg(long, default_value = "1024-65535")]
    port_range: String,
}

// Update the client struct to match the new writer approach
struct ConnectedClient {
    writer: Arc<Mutex<BufWriter<tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>>>>,
    tunnels: Arc<Mutex<HashMap<u16, TunnelInfo>>>,
}

impl ConnectedClient {
    fn _new(
        writer: BufWriter<tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>>,
    ) -> Self {
        Self {
            writer: Arc::new(Mutex::new(writer)),
            tunnels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn send_command(&self, cmd: &Command) -> Result<()> {
        let mut writer = self.writer.lock().await;
        let cmd_str = serde_json::to_string(&cmd).context("Failed to serialize command")? + "\n";
        writer.write_all(cmd_str.as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }
}

struct ServerState {
    clients: HashMap<String, Arc<ConnectedClient>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = ServerArgs::parse();

    // Parse port range
    let port_range: Vec<&str> = args.port_range.split('-').collect();
    if port_range.len() != 2 {
        anyhow::bail!("Invalid port range format. Expected 'min-max'");
    }
    let min_port = port_range[0]
        .parse::<u16>()
        .context("Invalid minimum port")?;
    let max_port = port_range[1]
        .parse::<u16>()
        .context("Invalid maximum port")?;

    // Load TLS certificates
    let key_pem = fs::read(&args.key).context("Failed to read private key file")?;
    let key = pkcs8_private_keys(&mut &key_pem[..])
        .map_err(|e| anyhow!("Failed to parse private key: {}", e))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("No private key found in file"))?;
    let key = PrivateKeyDer::Pkcs8(key.into());

    let cert_pem = fs::read(&args.cert).context("Failed to read certificate file")?;
    let certs = certs(&mut &cert_pem[..])
        .map_err(|e| anyhow!("Failed to parse certificate: {}", e))?
        .into_iter()
        .map(|cert| CertificateDer::from(cert))
        .collect::<Vec<_>>();

    if certs.is_empty() {
        anyhow::bail!("No certificates found in file");
    }

    // Build TLS config
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("TLS config error: {}", e))?;

    let acceptor = TlsAcceptor::from(Arc::new(config));

    // Create shared server state
    let state = Arc::new(Mutex::new(ServerState {
        clients: HashMap::new(),
    }));

    // Start command input handler
    let state_clone = state.clone();
    tokio::spawn(async move {
        handle_server_commands(state_clone).await;
    });

    // Bind TCP listener
    let listener = TcpListener::bind(&args.addr)
        .await
        .context("Failed to bind to address")?;
    println!("Listening on {}", args.addr);

    // Accept connections
    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        println!("TCP connection from {peer_addr}");

        let acceptor = acceptor.clone();
        let state = state.clone();
        let allow_udp = args.allow_udp;
        let min_port = min_port;
        let max_port = max_port;

        tokio::spawn(async move {
            if let Err(e) =
                handle_client(tcp_stream, acceptor, state, allow_udp, min_port, max_port).await
            {
                eprintln!("Error handling connection from {peer_addr}: {e}");
            }
        });
    }
}

async fn handle_client(
    tcp_stream: TcpStream,
    acceptor: TlsAcceptor,
    state: Arc<Mutex<ServerState>>,
    _allow_udp: bool,
    min_port: u16,
    max_port: u16,
) -> Result<()> {
    let tls_stream = acceptor
        .accept(tcp_stream)
        .await
        .context("TLS handshake failed")?;
    println!("TLS handshake completed");

    let (rd, wr) = tokio::io::split(tls_stream);
    let mut reader = BufReader::new(rd);
    let writer = BufWriter::new(wr);
    let mut buf = String::new();
    let mut client_id = None;

    let writer = Arc::new(Mutex::new(writer));

    loop {
        buf.clear();
        let n = reader
            .read_line(&mut buf)
            .await
            .context("Failed to read command")?;

        if n == 0 {
            if let Some(id) = client_id.as_ref() {
                let mut state = state.lock().await;
                state.clients.remove(id);
                println!("Client {id} disconnected");
            }
            return Ok(());
        }

        // Try to parse message as a Command first
        let parsed_command = serde_json::from_str::<Command>(&buf.trim());

        // Handle the message based on whether it's a command or not
        match parsed_command {
            Ok(cmd) => {
                println!("Received command: {:?}", cmd);

                match cmd {
                    Command::Register { client_id: id } => {
                        let mut state = state.lock().await;
                        let client = Arc::new(ConnectedClient {
                            writer: writer.clone(),
                            tunnels: Arc::new(Mutex::new(HashMap::new())),
                        });
                        state.clients.insert(id.clone(), client.clone());
                        client_id = Some(id.clone());
                        println!("Client registered: {id}");

                        let mut writer = client.writer.lock().await;
                        send_response(&mut *writer, &Response::Ok).await?;
                    }
                    Command::CreateTunnel {
                        local_port,
                        target_host,
                        target_port,
                        direction,
                    } => {
                        if let Some(ref id) = client_id {
                            let state = state.lock().await;
                            if let Some(client) = state.clients.get(id) {
                                if local_port < min_port || local_port > max_port {
                                    let mut writer = client.writer.lock().await;
                                    send_response(
                                        &mut *writer,
                                        &Response::Error(format!(
                                            "Port {} outside allowed range {}-{}",
                                            local_port, min_port, max_port
                                        )),
                                    )
                                    .await?;
                                    continue;
                                }

                                let mut tunnels = client.tunnels.lock().await;
                                tunnels.insert(local_port, TunnelInfo {
                                    local_port,
                                    target_host,
                                    target_port,
                                    direction,
                                    bytes_sent: 0,
                                    bytes_received: 0,
                                });

                                let mut writer = client.writer.lock().await;
                                send_response(&mut *writer, &Response::Ok).await?;
                            }
                        }
                    }
                    Command::ModifyTunnel {
                        old_local_port,
                        new_local_port,
                        new_target_host,
                        new_target_port,
                    } => {
                        if let Some(ref id) = client_id {
                            let state = state.lock().await;
                            if let Some(client) = state.clients.get(id) {
                                let mut tunnels = client.tunnels.lock().await;

                                // Remove old tunnel while preserving stats if they exist
                                let old_stats = tunnels
                                    .remove(&old_local_port)
                                    .map(|t| (t.bytes_sent, t.bytes_received))
                                    .unwrap_or((0, 0));

                                // Create new tunnel info with preserved stats
                                let new_tunnel = TunnelInfo {
                                    local_port: new_local_port,
                                    target_host: new_target_host.clone(),
                                    target_port: new_target_port,
                                    direction: TunnelDirection::Forward,
                                    bytes_sent: old_stats.0,
                                    bytes_received: old_stats.1,
                                };

                                // Insert new tunnel info
                                tunnels.insert(new_local_port, new_tunnel);

                                let mut writer = client.writer.lock().await;
                                send_response(&mut *writer, &Response::Ok).await?;

                                println!(
                                    "Updated tunnel mapping for client {}: {}:{} -> {}:{}",
                                    id,
                                    "localhost",
                                    new_local_port,
                                    new_target_host,
                                    new_target_port
                                );
                            }
                        }
                    }
                    Command::CloseTunnel { local_port } => {
                        if let Some(ref id) = client_id {
                            let state = state.lock().await;
                            if let Some(client) = state.clients.get(id) {
                                let mut tunnels = client.tunnels.lock().await;
                                tunnels.remove(&local_port);

                                let mut writer = client.writer.lock().await;
                                send_response(&mut *writer, &Response::Ok).await?;
                            }
                        }
                    }
                    Command::ListTunnels => {
                        if let Some(ref id) = client_id {
                            let state = state.lock().await;
                            if let Some(client) = state.clients.get(id) {
                                let tunnels = client.tunnels.lock().await;
                                let tunnel_list: Vec<TunnelInfo> =
                                    tunnels.values().cloned().collect();

                                let mut writer = client.writer.lock().await;
                                send_response(&mut *writer, &Response::TunnelList(tunnel_list))
                                    .await?;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                // If it's not a command, try to parse as a Response
                match serde_json::from_str::<Response>(&buf.trim()) {
                    Ok(response) => {
                        println!("Received response from client: {:?}", response);
                        // Handle client response if needed
                        continue;
                    }
                    Err(_) => {
                        // If it's neither a command nor a response, it's an error
                        eprintln!("Invalid message format: {}", e);
                        continue;
                    }
                }
            }
        }
    }
}

async fn handle_server_commands(state: Arc<Mutex<ServerState>>) {
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut buf = String::new();

    println!("Server command interface ready. Type 'help' for commands.");

    loop {
        buf.clear();
        print!("forge> ");
        let _ = std::io::Write::flush(&mut std::io::stdout());

        if stdin.read_line(&mut buf).await.unwrap() == 0 {
            break;
        }

        let parts: Vec<&str> = buf.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "help" => {
                println!("Available commands:");
                println!("  clients                     - List connected clients");
                println!("  tunnels <client_id>         - List tunnels for a client");
                println!(
                    "  create <client_id> <local_port> <target_host> <target_port> [-r] - Create tunnel"
                );
                println!("  modify <client_id> <local_port> <new_host> <new_port> - Modify tunnel");
                println!("  close <client_id> <local_port> - Close tunnel");
                println!("  exit                        - Shut down server");
            }
            "clients" => {
                let state = state.lock().await;
                println!("Connected clients:");
                for id in state.clients.keys() {
                    println!("  {}", id);
                }
            }
            "tunnels" => {
                if parts.len() != 2 {
                    println!("Usage: tunnels <client_id>");
                    continue;
                }

                let state = state.lock().await;
                if let Some(client) = state.clients.get(parts[1]) {
                    let tunnels = client.tunnels.lock().await;
                    println!("Active tunnels for {}:", parts[1]);
                    for tunnel in tunnels.values() {
                        println!(
                            "  {}:{} -> {}:{} ({:?})",
                            "localhost",
                            tunnel.local_port,
                            tunnel.target_host,
                            tunnel.target_port,
                            tunnel.direction
                        );
                    }
                } else {
                    println!("Client {} not found", parts[1]);
                }
            }
            "create" => {
                if parts.len() < 5 {
                    println!(
                        "Usage: create <client_id> <local_port> <target_host> <target_port> [-r]"
                    );
                    continue;
                }

                let client_id = parts[1];
                let local_port = match parts[2].parse::<u16>() {
                    Ok(port) => port,
                    Err(_) => {
                        println!("Invalid local port number");
                        continue;
                    }
                };
                let target_host = parts[3].to_string();
                let target_port = match parts[4].parse::<u16>() {
                    Ok(port) => port,
                    Err(_) => {
                        println!("Invalid target port number");
                        continue;
                    }
                };
                let direction = if parts.get(5) == Some(&"-r") {
                    TunnelDirection::Reverse
                } else {
                    TunnelDirection::Forward
                };

                let state = state.lock().await;
                if let Some(client) = state.clients.get(client_id) {
                    let cmd = Command::CreateTunnel {
                        local_port,
                        target_host,
                        target_port,
                        direction,
                    };
                    if let Err(e) = client.send_command(&cmd).await {
                        println!("Failed to send command: {}", e);
                    } else {
                        println!("Tunnel creation command sent successfully");
                    }
                } else {
                    println!("Client {} not found", client_id);
                }
            }
            "modify" => {
                if parts.len() != 5 {
                    println!("Usage: modify <client_id> <local_port> <new_host> <new_port>");
                    continue;
                }

                let client_id = parts[1];
                let local_port = match parts[2].parse::<u16>() {
                    Ok(port) => port,
                    Err(_) => {
                        println!("Invalid local port number");
                        continue;
                    }
                };
                let new_target_host = parts[3].to_string();
                let new_target_port = match parts[4].parse::<u16>() {
                    Ok(port) => port,
                    Err(_) => {
                        println!("Invalid target port number");
                        continue;
                    }
                };

                let state = state.lock().await;
                if let Some(client) = state.clients.get(client_id) {
                    let cmd = Command::ModifyTunnel {
                        old_local_port: local_port,
                        new_local_port: local_port, // Keep same local port
                        new_target_host,
                        new_target_port,
                    };
                    if let Err(e) = client.send_command(&cmd).await {
                        println!("Failed to send command: {}", e);
                    } else {
                        println!("Tunnel modification command sent successfully");
                    }
                } else {
                    println!("Client {} not found", client_id);
                }
            }
            "close" => {
                if parts.len() != 3 {
                    println!("Usage: close <client_id> <local_port>");
                    continue;
                }

                let client_id = parts[1];
                let local_port = match parts[2].parse::<u16>() {
                    Ok(port) => port,
                    Err(_) => {
                        println!("Invalid port number");
                        continue;
                    }
                };

                let state = state.lock().await;
                if let Some(client) = state.clients.get(client_id) {
                    let cmd = Command::CloseTunnel { local_port };
                    if let Err(e) = client.send_command(&cmd).await {
                        println!("Failed to send command: {}", e);
                    } else {
                        println!("Tunnel close command sent successfully");
                    }
                } else {
                    println!("Client {} not found", client_id);
                }
            }
            "exit" => {
                println!("Shutting down server...");
                break;
            }
            _ => {
                println!("Unknown command. Type 'help' for available commands.");
            }
        }
    }
}

async fn send_response(
    writer: &mut BufWriter<tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>>,
    response: &Response,
) -> Result<()> {
    let resp_text = serde_json::to_string(response).context("Failed to serialize response")?;
    writer
        .write_all(resp_text.as_bytes())
        .await
        .context("Failed to write response")?;
    writer
        .write_all(b"\n")
        .await
        .context("Failed to write newline")?;
    writer.flush().await.context("Failed to flush writer")?;
    Ok(())
}
