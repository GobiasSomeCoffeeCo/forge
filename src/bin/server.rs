// src/bin/server.rs
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use forge::protocol::{Command, Response};
use forge::tunnel::Tunnel;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

#[derive(Parser)]
struct ServerArgs {
    /// Address to listen on, e.g. "127.0.0.1:8443"
    #[arg(long, default_value = "127.0.0.1:8443")]
    addr: String,

    /// Path to server private key (PKCS8 PEM)
    #[arg(long)]
    key: PathBuf,

    /// Path to server certificate (PEM)
    #[arg(long)]
    cert: PathBuf,

    /// Allow UDP tunnels (default is TCP only)
    #[arg(long)]
    allow_udp: bool,

    /// Port range allowed for tunnels (e.g. "1024-65535")
    #[arg(long, default_value = "1024-65535")]
    port_range: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = ServerArgs::parse();

    // Parse port range
    let port_range: Vec<&str> = args.port_range.split('-').collect();
    if port_range.len() != 2 {
        anyhow::bail!("Invalid port range format. Expected 'min-max'");
    }
    let min_port = port_range[0].parse::<u16>()
        .context("Invalid minimum port")?;
    let max_port = port_range[1].parse::<u16>()
        .context("Invalid maximum port")?;

    // 1) Load server key pair
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

    // 2) Build TLS config
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("TLS config error: {}", e))?;
    
    let acceptor = TlsAcceptor::from(Arc::new(config));

    // 3) Bind TCP listener
    let listener = TcpListener::bind(&args.addr)
        .await
        .context("Failed to bind to address")?;
    println!("Listening on {}", args.addr);

    // 4) Accept connections
    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        println!("TCP connection from {peer_addr}");
        
        let acceptor = acceptor.clone();
        let allow_udp = args.allow_udp;
        let min_port = min_port;
        let max_port = max_port;

        // Spawn a new task for each connection
        tokio::spawn(async move {
            match handle_connection(tcp_stream, acceptor, allow_udp, min_port, max_port).await {
                Ok(()) => println!("Connection from {peer_addr} completed"),
                Err(e) => eprintln!("Error handling connection from {peer_addr}: {e}"),
            }
        });
    }
}

async fn handle_connection(
    tcp_stream: TcpStream,
    acceptor: TlsAcceptor,
    _allow_udp: bool,
    min_port: u16,
    max_port: u16,
) -> Result<()> {
    // Do TLS handshake
    let tls_stream = acceptor
        .accept(tcp_stream)
        .await
        .context("TLS handshake failed")?;
    println!("TLS handshake completed");

    let (rd, wr) = tokio::io::split(tls_stream);
    let mut reader = BufReader::new(rd);
    let mut writer = BufWriter::new(wr);
    let mut buf = String::new();

    loop {
        buf.clear();
        let n = reader
            .read_line(&mut buf)
            .await
            .context("Failed to read command")?;

        if n == 0 {
            println!("Client closed connection");
            return Ok(());
        }

        let cmd: Command = match serde_json::from_str(buf.trim()) {
            Ok(cmd) => cmd,
            Err(e) => {
                eprintln!("Invalid command JSON: {e}");
                let resp = Response::Error(format!("Invalid command JSON: {e}"));
                send_response(&mut writer, &resp).await?;
                continue;
            }
        };

        println!("Received command: {:?}", cmd);

        match cmd {
            Command::Register { client_id } => {
                println!("Client registered: {client_id}");
                send_response(&mut writer, &Response::Ok).await?;
            }
            Command::OpenTunnel { port } => {
                if port < min_port || port > max_port {
                    send_response(&mut writer, &Response::Error(
                        format!("Port {} outside allowed range {}-{}", port, min_port, max_port)
                    )).await?;
                    continue;
                }

                println!("Opening tunnel to port {port}");
                // Inside handle_connection, in the OpenTunnel match arm:
let target_stream = match TcpStream::connect(&format!("127.0.0.1:{port}")).await {
    Ok(stream) => stream,
    Err(e) => {
        send_response(&mut writer, &Response::Error(
            format!("Failed to connect to local port {}: {}", port, e)
        )).await?;
        continue;
    }
};

// Send success response before starting tunnel
send_response(&mut writer, &Response::Ok).await?;

// Setup tunnels - swap the order to make both sides match
let tls_stream = reader.into_inner().unsplit(writer.into_inner());
let mut server_tunnel = Tunnel::TLS(Box::new(tls_stream));
let mut target_tunnel = Tunnel::TCP(target_stream);

// Forward traffic
server_tunnel.forward_to(&mut target_tunnel).await?;
                return Ok(());
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