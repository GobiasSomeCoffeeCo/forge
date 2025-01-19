// src/bin/client.rs
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use forge::protocol::{Command, Response};
use forge::tunnel::Tunnel;
use tokio_rustls::rustls::pki_types::{CertificateDer, DnsName, ServerName};
use rustls_pemfile::certs;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
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
        let dns_name = DnsName::try_from(sni)
            .map_err(|_| anyhow!("Invalid server name (neither IP address nor valid DNS name): {}", sni))?;
        ServerName::DnsName(dns_name)
    };

    // 5) Initial connection for registration
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
    let cmd = Command::Register {
        client_id: format!("client-{}", args.local_port),
    };
    send_command(&mut writer, &mut reader, &cmd).await?;
    println!("Registered with server");

    // 7) Request tunnel opening
    let cmd = Command::OpenTunnel {
        port: args.remote_port,
    };
    send_command(&mut writer, &mut reader, &cmd).await?;
    println!("Tunnel established to remote port {}", args.remote_port);

    // 8) Start local listener and forwarding
    let local_addr = format!("127.0.0.1:{}", args.local_port);
    println!("Starting local listener on {}", local_addr);

    if args.udp {
        let mut local_tunnel = Tunnel::new_udp(&local_addr, None).await?;
        let tcp = TcpStream::connect(&args.server).await?;
        let tls_stream = create_tls_connection(tcp, client_config, server_name).await?;
        let mut server_tunnel = Tunnel::TLS(Box::new(tls_stream));
        println!("UDP tunnel active");
        local_tunnel.forward_to(&mut server_tunnel).await?;
    } else {
        let listener = TcpListener::bind(&local_addr).await?;
        println!("TCP tunnel active");
        
        let server_addr = args.server.clone();
        let config = client_config.clone();
        let server_name = server_name.clone();
        
        loop {
            let (socket, peer) = listener.accept().await?;
            println!("New connection from {}", peer);
            
            let server_addr = server_addr.clone();
            let config = config.clone();
            let server_name = server_name.clone();
            
            tokio::spawn(async move {
                let result: Result<()> = async {
                    let tcp = TcpStream::connect(&server_addr).await
                        .context("Failed to establish TCP connection")?;
                    
                    let tls_stream = create_tls_connection(tcp, config, server_name).await?;
                    let mut server_tunnel = Tunnel::TLS(Box::new(tls_stream));
                    let mut local_tunnel = Tunnel::TCP(socket);

                    local_tunnel.forward_to(&mut server_tunnel).await?;
                    Ok(())
                }.await;

                if let Err(e) = result {
                    eprintln!("Connection error for {}: {}", peer, e);
                }
            });
        }
    }

    Ok(())
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
        Err(e) => Err(anyhow!("Failed to parse server response: {}", e)),
    }
}