include!(concat!(env!("OUT_DIR"), "/config.rs"));

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use forge::protocol::{Command, Response, TunnelDirection, TunnelInfo};
use forge::socks::{SocksConfig, SocksProxy};
use rustls_pemfile::certs;
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, DnsName, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

#[derive(Parser)]
struct ClientArgs {
    /// Server address, e.g. "127.0.0.1:8443"
    #[arg(long, default_value = "127.0.0.1:8443")]
    server: String,

    /// Path to CA certificate (PEM) to trust
    #[arg(long)]
    ca: PathBuf,

    /// SNI name
    #[arg(long, default_value = "localhost")]
    sni: String,
}

#[allow(dead_code)]
struct TunnelConfig {
    local_port: u16,
    target_host: String,
    target_port: u16,
    shutdown: tokio::sync::broadcast::Sender<()>,
}

struct TunnelManager {
    tunnels: Mutex<HashMap<u16, TunnelConfig>>,
    socks_proxy: Mutex<Option<SocksProxy>>,
    socks_tunnels: Mutex<HashMap<u16, tokio::sync::mpsc::Sender<Vec<u8>>>>,
    active_connections: Arc<tokio::sync::Mutex<HashMap<u32, TcpStream>>>,
}

impl TunnelManager {
    fn new() -> Self {
        Self {
            tunnels: Mutex::new(HashMap::new()),
            socks_proxy: Mutex::new(None),
            socks_tunnels: Mutex::new(HashMap::new()),
            active_connections: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    fn get_target(&self, local_port: u16) -> Option<(String, u16)> {
        let tunnels = self.tunnels.lock().unwrap();
        tunnels
            .get(&local_port)
            .map(|config| (config.target_host.clone(), config.target_port))
    }

    fn modify_tunnel(
        &self,
        old_port: u16,
        new_port: u16,
        new_host: String,
        new_target_port: u16,
    ) -> Result<()> {
        let mut tunnels = self.tunnels.lock().unwrap();

        // Send shutdown signal if old tunnel exists
        if let Some(old_config) = tunnels.remove(&old_port) {
            let _ = old_config.shutdown.send(());
        }

        // Create new tunnel config
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        let new_config = TunnelConfig {
            local_port: new_port,
            target_host: new_host.clone(),
            target_port: new_target_port,
            shutdown: shutdown_tx,
        };

        tunnels.insert(new_port, new_config);
        Ok(())
    }
}

async fn create_tls_connection(
    tcp: TcpStream,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let connector = TlsConnector::from(config);
    connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")
}

async fn start_tcp_tunnel_listener(local_port: u16, tunnel_manager: Arc<TunnelManager>) -> Result<()> {
    let local_addr = format!("0.0.0.0:{}", local_port);

    let listener = loop {
        match TcpListener::bind(&local_addr).await {
            Ok(l) => {
                println!("Successfully bound to {}", local_addr);
                break l;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                println!(
                    "Port {} still in use, waiting 100ms before retry...",
                    local_port
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
            Err(e) => return Err(anyhow!("Failed to bind to {}: {}", local_addr, e)),
        }
    };

    let mut shutdown_rx = {
        let tunnels = tunnel_manager.tunnels.lock().unwrap();
        tunnels
            .get(&local_port)
            .ok_or_else(|| anyhow!("No tunnel configuration found for port {}", local_port))?
            .shutdown
            .subscribe()
    };

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((socket, peer_addr)) => {
                        println!("New connection from {} on port {}", peer_addr, local_port);
                        let tunnel_manager = tunnel_manager.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(socket, tunnel_manager, local_port).await {
                                eprintln!("Connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Accept error on port {}: {}", local_port, e);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                println!("Received shutdown signal for listener on port {}", local_port);
                return Ok(());
            }
        }
    }
}

async fn handle_connection(
    mut local_socket: TcpStream,
    tunnel_manager: Arc<TunnelManager>,
    local_port: u16,
) -> Result<()> {
    let (target_host, target_port) = tunnel_manager
        .get_target(local_port)
        .ok_or_else(|| anyhow!("No tunnel configuration found for port {}", local_port))?;

    println!("Connecting to target {}:{}", target_host, target_port);

    let mut target_socket = TcpStream::connect(format!("{}:{}", target_host, target_port))
        .await
        .context("Failed to connect to target")?;

    let (mut local_rd, mut local_wr) = local_socket.split();
    let (mut target_rd, mut target_wr) = target_socket.split();

    let client_to_target = async {
        let mut buf = [0u8; 32768];
        loop {
            let n = local_rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            target_wr.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let target_to_client = async {
        let mut buf = [0u8; 32768];
        loop {
            let n = target_rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            local_wr.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(client_to_target, target_to_client)?;
    Ok(())
}

async fn send_command(
    writer: &mut BufWriter<tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    reader: &mut BufReader<tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    cmd: &Command,
) -> Result<()> {
    let cmd_text = serde_json::to_string(cmd)? + "\n";
    writer.write_all(cmd_text.as_bytes()).await?;
    writer.flush().await?;

    let mut buf = String::new();
    reader.read_line(&mut buf).await?;

    match serde_json::from_str::<Response>(&buf.trim()) {
        Ok(Response::Ok) => Ok(()),
        Ok(Response::Error(e)) => Err(anyhow!("Server error: {}", e)),
        Ok(Response::TunnelList(_)) => Ok(()),
        Ok(Response::SocksData { .. }) => Ok(()), // SOCKS data response
        Err(e) => Err(anyhow!("Failed to parse server response: {}", e)),
    }
}

async fn start_udp_tunnel_listener(local_port: u16, tunnel_manager: Arc<TunnelManager>) -> Result<()> {
    use tokio::net::UdpSocket;
    
    let local_addr = format!("0.0.0.0:{}", local_port);
    let socket = UdpSocket::bind(&local_addr).await
        .with_context(|| format!("Failed to bind UDP socket to {}", local_addr))?;
    
    println!("UDP tunnel listener started on {}", local_addr);

    let mut shutdown_rx = {
        let tunnels = tunnel_manager.tunnels.lock().unwrap();
        tunnels
            .get(&local_port)
            .ok_or_else(|| anyhow!("No tunnel configuration found for port {}", local_port))?
            .shutdown
            .subscribe()
    };

    let mut buf = vec![0u8; 32768];
    
    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, peer_addr)) => {
                        let (target_host, target_port) = {
                            let tunnels = tunnel_manager.tunnels.lock().unwrap();
                            if let Some(config) = tunnels.get(&local_port) {
                                (config.target_host.clone(), config.target_port)
                            } else {
                                eprintln!("No tunnel config found for port {}", local_port);
                                continue;
                            }
                        };

                        // Forward UDP packet to target
                        if let Ok(target_addr) = format!("{}:{}", target_host, target_port).parse::<std::net::SocketAddr>() {
                            if let Ok(target_socket) = UdpSocket::bind("0.0.0.0:0").await {
                                if let Err(e) = target_socket.send_to(&buf[..n], target_addr).await {
                                    eprintln!("Failed to forward UDP packet: {}", e);
                                }
                                
                                // Listen for response (simplified - in practice you'd want better state management)
                                let mut response_buf = vec![0u8; 32768];
                                tokio::select! {
                                    result = target_socket.recv_from(&mut response_buf) => {
                                        if let Ok((resp_n, _)) = result {
                                            if let Err(e) = socket.send_to(&response_buf[..resp_n], peer_addr).await {
                                                eprintln!("Failed to send UDP response: {}", e);
                                            }
                                        }
                                    }
                                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                                        // Timeout waiting for response
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("UDP recv error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                println!("UDP tunnel on port {} shutting down", local_port);
                break;
            }
        }
    }
    
    Ok(())
}

async fn send_response(
    writer: &mut BufWriter<tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    response: &Response,
) -> Result<()> {
    let resp_text = serde_json::to_string(response)? + "\n";
    writer.write_all(resp_text.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

async fn handle_server_commands(
    mut reader: BufReader<tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    mut writer: BufWriter<tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    tunnel_manager: Arc<TunnelManager>,
) -> Result<()> {
    println!("Command handler initialized and waiting for commands...");
    let mut buf = String::new();

    loop {
        buf.clear();

        let n = match reader.read_line(&mut buf).await {
            Ok(n) => {
                println!("Read {} bytes from command channel", n);
                n
            }
            Err(e) => {
                eprintln!("Error reading from command channel: {}", e);
                return Err(anyhow!("Command channel read error: {}", e));
            }
        };

        if n == 0 {
            println!("Server closed command channel");
            return Ok(());
        }

        println!("Received raw command: {}", buf.trim());

        // First try to parse as a Command
        let cmd: Command = match serde_json::from_str(buf.trim()) {
            Ok(cmd) => {
                println!("Parsed command successfully: {:?}", cmd);
                cmd
            }
            Err(_) => {
                // If it's not a command, try to parse as a Response
                if let Ok(response) = serde_json::from_str::<Response>(buf.trim()) {
                    println!("Received response: {:?}", response);
                    continue;
                } else {
                    eprintln!("Failed to parse message as command or response");
                    continue;
                }
            }
        };

        match cmd {
            Command::ModifyTunnel {
                old_local_port,
                new_local_port,
                new_target_host,
                new_target_port,
            } => {
                println!(
                    "Processing modify tunnel command: {} -> {} ({} -> {})",
                    old_local_port, new_local_port, new_target_host, new_target_port
                );

                if let Err(e) = tunnel_manager.modify_tunnel(
                    old_local_port,
                    new_local_port,
                    new_target_host.clone(),
                    new_target_port,
                ) {
                    eprintln!("Failed to modify tunnel: {}", e);
                    send_response(&mut writer, &Response::Error(e.to_string())).await?;
                    continue;
                }

                let tm = tunnel_manager.clone();
                tokio::spawn(async move {
                    if let Err(e) = start_tcp_tunnel_listener(new_local_port, tm).await {
                        eprintln!("Failed to start tunnel listener: {}", e);
                    }
                });

                send_response(&mut writer, &Response::Ok).await?;
            }
            Command::CreateTunnel {
                local_port,
                target_host,
                target_port,
                direction: _,
                protocol,
            } => {
                if let Err(e) = tunnel_manager.modify_tunnel(
                    local_port,
                    local_port,
                    target_host.clone(),
                    target_port,
                ) {
                    send_response(&mut writer, &Response::Error(e.to_string())).await?;
                    continue;
                }

                let tm = tunnel_manager.clone();
                tokio::spawn(async move {
                    match protocol {
                        forge::protocol::TunnelProtocol::Tcp => {
                            if let Err(e) = start_tcp_tunnel_listener(local_port, tm).await {
                                eprintln!("Failed to start TCP tunnel listener: {}", e);
                            }
                        }
                        forge::protocol::TunnelProtocol::Udp => {
                            if let Err(e) = start_udp_tunnel_listener(local_port, tm).await {
                                eprintln!("Failed to start UDP tunnel listener: {}", e);
                            }
                        }
                        forge::protocol::TunnelProtocol::Socks5 => {
                            eprintln!("SOCKS5 protocol should use separate SOCKS proxy functionality");
                        }
                    }
                });

                send_response(&mut writer, &Response::Ok).await?;
            }
            Command::CloseTunnel { local_port } => {
                let send_result = {
                    let tunnels = tunnel_manager.tunnels.lock().unwrap();
                    tunnels
                        .get(&local_port)
                        .map(|config| config.shutdown.send(()))
                };

                match send_result {
                    Some(_) => send_response(&mut writer, &Response::Ok).await?,
                    None => {
                        send_response(
                            &mut writer,
                            &Response::Error(format!("No tunnel found on port {}", local_port)),
                        )
                        .await?;
                    }
                }
            }
            Command::ListTunnels => {
                let tunnel_list = {
                    let tunnels = tunnel_manager.tunnels.lock().unwrap();
                    tunnels
                        .iter()
                        .map(|(&port, config)| TunnelInfo {
                            local_port: port,
                            target_host: config.target_host.clone(),
                            target_port: config.target_port,
                            direction: TunnelDirection::Forward,
                            protocol: forge::protocol::TunnelProtocol::Tcp,
                            bytes_sent: 0,
                            bytes_received: 0,
                            connections_active: 0,
                            connections_total: 0,
                        })
                        .collect::<Vec<_>>()
                };

                send_response(&mut writer, &Response::TunnelList(tunnel_list)).await?;
            }
            Command::Register { client_id } => {
                println!("Registered as client {}", client_id);
                send_response(&mut writer, &Response::Ok).await?;
            }
            Command::StartSocksProxy { bind_port, timeout } => {
                println!("Starting SOCKS5 proxy on port {}", bind_port);
                
                let mut socks_proxy_guard = tunnel_manager.socks_proxy.lock().unwrap();
                
                if socks_proxy_guard.is_some() {
                    send_response(&mut writer, &Response::Error("SOCKS proxy already running".to_string())).await?;
                } else {
                    let config = SocksConfig {
                        bind_addr: format!("0.0.0.0:{}", bind_port).parse().unwrap(),
                        timeout: Duration::from_secs(timeout),
                        enable_udp: true,
                    };
                    
                    let mut proxy = SocksProxy::new(config);
                    
                    // Start the proxy in a background task
                    tokio::spawn(async move {
                        if let Err(e) = proxy.start().await {
                            eprintln!("SOCKS proxy error: {}", e);
                        }
                    });
                    
                    // Store a tracking proxy instance
                    let tracking_proxy = SocksProxy::new(SocksConfig {
                        bind_addr: format!("0.0.0.0:{}", bind_port).parse().unwrap(),
                        timeout: Duration::from_secs(timeout),
                        enable_udp: true,
                    });
                    
                    *socks_proxy_guard = Some(tracking_proxy);
                    
                    println!("SOCKS5 proxy started on port {}", bind_port);
                    send_response(&mut writer, &Response::Ok).await?;
                }
            }
            Command::StopSocksProxy => {
                println!("Stopping SOCKS5 proxy");
                
                let mut socks_proxy_guard = tunnel_manager.socks_proxy.lock().unwrap();
                
                if socks_proxy_guard.is_none() {
                    send_response(&mut writer, &Response::Error("No SOCKS proxy running".to_string())).await?;
                } else {
                    *socks_proxy_guard = None;
                    println!("SOCKS5 proxy stopped");
                    send_response(&mut writer, &Response::Ok).await?;
                }
            }
            Command::ScanPorts { .. } => {
                // TODO: Implement port scanning on client side
                send_response(&mut writer, &Response::Error("Not implemented".to_string())).await?;
            }
            Command::StartSocksTunnel { local_port, timeout } => {
                println!("Starting SOCKS tunnel on port {}", local_port);
                
                // Create a SOCKS proxy that will handle connections
                let config = forge::socks::SocksConfig {
                    bind_addr: format!("0.0.0.0:{}", local_port).parse().unwrap(),
                    timeout: Duration::from_secs(timeout),
                    enable_udp: true,
                };
                
                let mut proxy = forge::socks::SocksProxy::new(config);
                
                // Start the proxy in a background task
                tokio::spawn(async move {
                    if let Err(e) = proxy.start().await {
                        eprintln!("SOCKS tunnel proxy error: {}", e);
                    }
                });
                
                send_response(&mut writer, &Response::Ok).await?;
            }
            Command::StopSocksTunnel { local_port } => {
                println!("Stopping SOCKS tunnel on port {}", local_port);
                
                // Clean up the tunnel
                {
                    let mut tunnels = tunnel_manager.socks_tunnels.lock().unwrap();
                    tunnels.remove(&local_port);
                }
                
                send_response(&mut writer, &Response::Ok).await?;
            }
            Command::SocksData { local_port, connection_id, data } => {
                // Handle SOCKS data from server - parse SOCKS protocol and forward to target
                if data.len() < 4 {
                    // Invalid SOCKS data
                    let response = Response::SocksData {
                        local_port,
                        connection_id,
                        data: vec![0x00, 0x5B], // SOCKS4 general failure
                    };
                    send_response(&mut writer, &response).await?;
                    continue;
                }

                // Handle SOCKS4 CONNECT command
                if data[0] == 0x04 && data[1] == 0x01 && data.len() >= 8 {
                    let target_port = u16::from_be_bytes([data[2], data[3]]);
                    let target_ip = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
                    
                    println!("SOCKS4 connection request to {}:{}", target_ip, target_port);
                    
                    match TcpStream::connect(format!("{}:{}", target_ip, target_port)).await {
                        Ok(_target_stream) => {
                            let response = Response::SocksData {
                                local_port,
                                connection_id,
                                data: vec![0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // SOCKS4 success
                            };
                            send_response(&mut writer, &response).await?;
                            println!("SOCKS4 connection established to {}:{}", target_ip, target_port);
                        }
                        Err(e) => {
                            println!("SOCKS4 connection failed to {}:{}: {}", target_ip, target_port, e);
                            let response = Response::SocksData {
                                local_port,
                                connection_id,
                                data: vec![0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // SOCKS4 rejection
                            };
                            send_response(&mut writer, &response).await?;
                        }
                    }
                    continue;
                }

                // Handle SOCKS5 authentication negotiation  
                if data[0] == 0x05 && data.len() >= 2 && data[1] == 0x01 {
                    let response = Response::SocksData {
                        local_port,
                        connection_id,
                        data: vec![0x05, 0x00], // No authentication required
                    };
                    send_response(&mut writer, &response).await?;
                    println!("SOCKS5 authentication negotiation completed");
                    continue;
                }

                // Simple SOCKS5 CONNECT command parsing
                if data[0] == 0x05 && data[1] == 0x01 && data[2] == 0x00 {
                    // SOCKS5 CONNECT command
                    let addr_type = data[3];
                    let (target_host, target_port, response_data) = match addr_type {
                        0x01 => {
                            // IPv4
                            if data.len() < 10 {
                                (String::new(), 0, vec![0x05, 0x01])
                            } else {
                                let ip = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
                                let port = u16::from_be_bytes([data[8], data[9]]);
                                (ip, port, vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                            }
                        }
                        0x03 => {
                            // Domain name
                            if data.len() < 5 {
                                (String::new(), 0, vec![0x05, 0x01])
                            } else {
                                let domain_len = data[4] as usize;
                                if data.len() < 5 + domain_len + 2 {
                                    (String::new(), 0, vec![0x05, 0x01])
                                } else {
                                    let domain = String::from_utf8_lossy(&data[5..5 + domain_len]).to_string();
                                    let port = u16::from_be_bytes([data[5 + domain_len], data[5 + domain_len + 1]]);
                                    (domain, port, vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                                }
                            }
                        }
                        _ => {
                            // Unsupported address type
                            (String::new(), 0, vec![0x05, 0x08]) // Address type not supported
                        }
                    };

                    if !target_host.is_empty() && target_port > 0 {
                        // Try to connect to target
                        match TcpStream::connect(format!("{}:{}", target_host, target_port)).await {
                            Ok(_target_stream) => {
                                // Connection successful - send success response
                                let response = Response::SocksData {
                                    local_port,
                                    connection_id,
                                    data: response_data,
                                };
                                send_response(&mut writer, &response).await?;
                                
                                // Store connection for future data forwarding
                                // (In a complete implementation, you'd maintain persistent connections)
                                println!("SOCKS5 connection established to {}:{}", target_host, target_port);
                            }
                            Err(_) => {
                                // Connection failed
                                let response = Response::SocksData {
                                    local_port,
                                    connection_id,
                                    data: vec![0x05, 0x05], // Connection refused
                                };
                                send_response(&mut writer, &response).await?;
                            }
                        }
                    } else {
                        // Invalid target
                        let response = Response::SocksData {
                            local_port,
                            connection_id,
                            data: vec![0x05, 0x01], // General failure
                        };
                        send_response(&mut writer, &response).await?;
                    }
                } else if data[0] == 0x05 && data[1] == 0x00 {
                    // SOCKS5 authentication request - no auth required
                    let response = Response::SocksData {
                        local_port,
                        connection_id,
                        data: vec![0x05, 0x00], // No authentication required
                    };
                    send_response(&mut writer, &response).await?;
                } else {
                    // For data forwarding after connection is established, we would forward to the target
                    // This is a simplified implementation - echo back for now
                    let response = Response::SocksData {
                        local_port,
                        connection_id,
                        data: data.clone(),
                    };
                    send_response(&mut writer, &response).await?;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Use the embedded constants directly
    let server_address = SERVER_ADDRESS;
    let server_sni = SERVER_SNI;
    let ca_cert = CA_CERT;

    // Parse the embedded CA cert
    let ca_certs = certs(&mut ca_cert.as_bytes())
        .map_err(|e| anyhow!("Failed to parse CA cert: {}", e))?
        .into_iter()
        .map(|cert| CertificateDer::from(cert))
        .collect::<Vec<_>>();

    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| anyhow!("Failed to add CA cert to store: {:?}", e))?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let client_config = Arc::new(config);

    // Set up server name for TLS
    let server_name = if let Ok(ip) = IpAddr::from_str(&server_sni) {
        ServerName::IpAddress(ip.into())
    } else {
        let dns_name = DnsName::try_from(server_sni).map_err(|_| {
            anyhow!(
                "Invalid server name (neither IP address nor valid DNS name): {}",
                server_sni
            )
        })?;
        ServerName::DnsName(dns_name)
    };

    // Initialize tunnel manager
    let tunnel_manager = Arc::new(TunnelManager::new());

    // Set up command channel connection
    println!(
        "Establishing command channel connection to {}...",
        server_address
    );
    let cmd_tcp = TcpStream::connect(&server_address)
        .await
        .context("Failed to establish command TCP connection")?;
    let cmd_tls = create_tls_connection(cmd_tcp, client_config, server_name).await?;
    println!("Command channel TLS established");

    let (cmd_rd, cmd_wr) = tokio::io::split(cmd_tls);
    let mut cmd_reader = BufReader::new(cmd_rd);
    let mut cmd_writer = BufWriter::new(cmd_wr);

    let binary_name = env::args()
        .next()
        .map(|p| {
            Path::new(&p)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("client")
                .to_string()
        })
        .unwrap_or("client".to_string());

    // Generate a unique client ID
    let client_id = format!(
        "{}-{}",
        binary_name,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    // Register with server
    let register_cmd = Command::Register {
        client_id: client_id.clone(),
    };
    send_command(&mut cmd_writer, &mut cmd_reader, &register_cmd).await?;
    println!("Registered with server as {}", client_id);

    // Main command handling loop using command handler
    let cmd_tunnel_manager = tunnel_manager.clone();

    // Use a separate scope for the command handler
    {
        let command_handler = handle_server_commands(cmd_reader, cmd_writer, cmd_tunnel_manager);
        tokio::pin!(command_handler);

        tokio::select! {
            result = &mut command_handler => {
                if let Err(e) = result {
                    eprintln!("Command handler error: {}", e);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("Received Ctrl+C, shutting down...");
            }
        }
    }

    println!("Shutdown complete");
    Ok(())
}
