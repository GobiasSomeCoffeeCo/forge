include!(concat!(env!("OUT_DIR"), "/config.rs"));

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use forge::protocol::{Command, Response, TunnelDirection, TunnelInfo};
use rustls_pemfile::certs;
use toml::Value;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, DnsName, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

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

struct TunnelConfig {
    local_port: u16,
    target_host: String,
    target_port: u16,
    shutdown: tokio::sync::broadcast::Sender<()>,
}

struct TunnelManager {
    tunnels: Mutex<HashMap<u16, TunnelConfig>>,
}

impl TunnelManager {
    fn new() -> Self {
        Self {
            tunnels: Mutex::new(HashMap::new()),
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

async fn start_tunnel_listener(local_port: u16, tunnel_manager: Arc<TunnelManager>) -> Result<()> {
    let local_addr = format!("0.0.0.0:{}", local_port);
    
    let listener = loop {
        match TcpListener::bind(&local_addr).await {
            Ok(l) => {
                println!("Successfully bound to {}", local_addr);
                break l;
            },
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                println!("Port {} still in use, waiting 100ms before retry...", local_port);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            },
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
        let mut buf = [0u8; 8192];
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
        let mut buf = [0u8; 8192];
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
        Err(e) => Err(anyhow!("Failed to parse server response: {}", e)),
    }
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
            },
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

        // First try to parse as a Response, in case the server sent us a response
        if let Ok(response) = serde_json::from_str::<Response>(buf.trim()) {
            println!("Received response: {:?}", response);
            continue;
        }

        // If it's not a response, try to parse as a Command
        let cmd: Command = match serde_json::from_str(buf.trim()) {
            Ok(cmd) => {
                println!("Parsed command successfully: {:?}", cmd);
                cmd
            },
            Err(e) => {
                eprintln!("Failed to parse message as command: {}", e);
                continue;
            }
        };

        match cmd {
            Command::ModifyTunnel { old_local_port, new_local_port, new_target_host, new_target_port } => {
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
                    if let Err(e) = start_tunnel_listener(new_local_port, tm).await {
                        eprintln!("Failed to start tunnel listener: {}", e);
                    }
                });

                send_response(&mut writer, &Response::Ok).await?;
            },
            Command::CreateTunnel { local_port, target_host, target_port, direction: _ } => {
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
                    if let Err(e) = start_tunnel_listener(local_port, tm).await {
                        eprintln!("Failed to start tunnel listener: {}", e);
                    }
                });

                send_response(&mut writer, &Response::Ok).await?;
            },
            Command::CloseTunnel { local_port } => {
                let send_result = {
                    let tunnels = tunnel_manager.tunnels.lock().unwrap();
                    tunnels.get(&local_port).map(|config| config.shutdown.send(()))
                };

                match send_result {
                    Some(_) => send_response(&mut writer, &Response::Ok).await?,
                    None => {
                        send_response(
                            &mut writer,
                            &Response::Error(format!("No tunnel found on port {}", local_port))
                        ).await?;
                    }
                }
            },
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
                            bytes_sent: 0,
                            bytes_received: 0,
                        })
                        .collect::<Vec<_>>()
                };

                send_response(&mut writer, &Response::TunnelList(tunnel_list)).await?;
            },
            Command::Register { client_id } => {
                println!("Registered as client {}", client_id);
                send_response(&mut writer, &Response::Ok).await?;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Read and parse config.toml
    let config_str = fs::read_to_string("config.toml")
        .context("Failed to read config.toml")?;
    let config: Value = toml::from_str(&config_str)
        .context("Failed to parse config.toml")?;

    // Extract values from config early and own them
    let server_address = config["server_address"].as_str()
        .ok_or_else(|| anyhow!("server_address not found in config"))?
        .to_string();
    
        let server_sni: &'static str = Box::leak(match config["server_sni"].as_str() {
            Some(sni) => sni.to_string().into_boxed_str(),
            None => server_address.split(':').next().unwrap().to_string().into_boxed_str()
        });

    let ca_cert_path = config["ca_cert"].as_str()
        .ok_or_else(|| anyhow!("ca_cert not found in config"))?
        .to_string();

    // Read CA certificate
    let ca_cert = fs::read_to_string(&ca_cert_path)
        .context("Failed to read CA certificate")?;

    // Parse the CA cert
    let ca_certs = certs(&mut ca_cert.as_bytes())
        .map_err(|e| anyhow!("Failed to parse CA cert: {}", e))?
        .into_iter()
        .map(|cert| CertificateDer::from(cert))
        .collect::<Vec<_>>();

    if ca_certs.is_empty() {
        anyhow::bail!("No CA certs found in certificate");
    }

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
            anyhow!("Invalid server name (neither IP address nor valid DNS name): {}", server_sni)
        })?;
        ServerName::DnsName(dns_name)
    };

    // Initialize tunnel manager
    let tunnel_manager = Arc::new(TunnelManager::new());
    
    // Set up command channel connection
    println!("Establishing command channel connection to {}...", server_address);
    let cmd_tcp = TcpStream::connect(&server_address)
        .await
        .context("Failed to establish command TCP connection")?;
    let cmd_tls = create_tls_connection(cmd_tcp, client_config, server_name).await?;
    println!("Command channel TLS established");

    let (cmd_rd, cmd_wr) = tokio::io::split(cmd_tls);
    let mut cmd_reader = BufReader::new(cmd_rd);
    let mut cmd_writer = BufWriter::new(cmd_wr);

    // Generate a unique client ID
    let client_id = format!(
        "client-{}",
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