// src/bin/client.rs
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use forge::protocol::{Command, Response, TunnelDirection};
use rustls_pemfile::certs;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpStream, TcpListener};
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

    /// Local port to listen on
    #[arg(long)]
    local_port: u16,

    /// Remote port to forward to
    #[arg(long)]
    remote_port: u16,

    /// Use UDP instead of TCP for the tunnel
    #[arg(long)]
    udp: bool,
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

async fn send_command(
    writer: &mut BufWriter<tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    reader: &mut BufReader<tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    cmd: &Command,
) -> Result<()> {
    let cmd_text = serde_json::to_string(cmd).context("Failed to serialize command")?;
    writer
        .write_all(cmd_text.as_bytes())
        .await
        .context("Failed to write command")?;
    writer
        .write_all(b"\n")
        .await
        .context("Failed to write newline")?;
    writer.flush().await.context("Failed to flush writer")?;

    let mut buf = String::new();
    let n = reader
        .read_line(&mut buf)
        .await
        .context("Failed to read response")?;

    if n == 0 {
        anyhow::bail!("Server closed connection unexpectedly");
    }

    match serde_json::from_str::<Response>(&buf.trim()) {
        Ok(Response::Ok) => Ok(()),
        Ok(Response::Error(e)) => Err(anyhow!("Server error: {}", e)),
        Ok(Response::TunnelList(_)) => Ok(()),
        Err(e) => Err(anyhow!("Failed to parse server response: {}", e)),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = ClientArgs::parse();

    // 1) Load CA cert
    let ca_pem = fs::read(&args.ca).context("Failed reading CA file")?;
    let ca_certs = certs(&mut &ca_pem[..])
        .map_err(|e| anyhow!("Failed to parse CA cert: {}", e))?
        .into_iter()
        .map(|cert| CertificateDer::from(cert))
        .collect::<Vec<_>>();

    if ca_certs.is_empty() {
        anyhow::bail!("No CA certs found in file");
    }

    // 2) Build a RootCertStore
    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| anyhow!("Failed to add CA cert to store: {:?}", e))?;
    }

    // 3) Build rustls ClientConfig
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let client_config = Arc::new(config);

    // 4) Create server name
    let sni = Box::leak(args.sni.into_boxed_str()) as &str;
    let server_name = if let Ok(ip) = IpAddr::from_str(sni) {
        ServerName::IpAddress(ip.into())
    } else {
        let dns_name = DnsName::try_from(sni).map_err(|_| {
            anyhow!(
                "Invalid server name (neither IP address nor valid DNS name): {}",
                sni
            )
        })?;
        ServerName::DnsName(dns_name)
    };

    // 5) Initial connection
    let tcp = TcpStream::connect(&args.server)
        .await
        .context("Failed to establish TCP connection")?;
    println!("TCP connected to {}", args.server);

    let tls_stream = create_tls_connection(tcp, client_config.clone(), server_name.clone()).await?;
    println!("TLS handshake OK!");

    // Split for command handling
    let (rd, wr) = tokio::io::split(tls_stream);
    let mut reader = BufReader::new(rd);
    let mut writer = BufWriter::new(wr);

    // 6) Register with server
    let client_id = format!("client-{}-{}", args.local_port, 
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs());
    
    let cmd = Command::Register {
        client_id: client_id.clone(),
    };
    send_command(&mut writer, &mut reader, &cmd).await?;
    println!("Registered with server as {}", client_id);

    // 7) Request tunnel opening
    let cmd = Command::CreateTunnel {
        local_port: args.local_port,
        target_host: "localhost".to_string(),
        target_port: args.remote_port,
        direction: TunnelDirection::Forward,
    };
    send_command(&mut writer, &mut reader, &cmd).await?;
    println!("Tunnel established: localhost:{} -> localhost:{}", 
        args.local_port, args.remote_port);

    // Start local listener
    let local_addr = format!("127.0.0.1:{}", args.local_port);
    let listener = TcpListener::bind(&local_addr)
        .await
        .context("Failed to bind local port")?;

// Handle incoming connections
loop {
    tokio::select! {
        accept_result = listener.accept() => {
            match accept_result {
                Ok((socket, peer_addr)) => {
                    println!("New connection from {}", peer_addr);
                    
                    // Connect to target
                    match TcpStream::connect(format!("localhost:{}", args.remote_port)).await {
                        Ok(target) => {
                            // Clone necessary handles
                            let config = client_config.clone();
                            let server_name = server_name.clone();
                            let server_addr = args.server.clone();
                            let client_id = client_id.clone();
                            
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    socket,
                                    target,
                                    &server_addr,
                                    config,
                                    server_name,
                                    &client_id,
                                    args.remote_port
                                ).await {
                                    eprintln!("Connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to target: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("Shutting down...");
            break;
        }
    }}
    
    Ok(())
}

async fn handle_connection(
    mut local_socket: TcpStream,
    mut target_socket: TcpStream,
    server_addr: &str,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    client_id: &str,
    remote_port: u16,
) -> Result<()> {
    let (mut local_rd, mut local_wr) = local_socket.split();
    let (mut target_rd, mut target_wr) = target_socket.split();

    let client_to_target = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = local_rd.read(&mut buf).await?;
            if n == 0 { break; }
            target_wr.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let target_to_client = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = target_rd.read(&mut buf).await?;
            if n == 0 { break; }
            local_wr.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(client_to_target, target_to_client)?;
    Ok(())
}