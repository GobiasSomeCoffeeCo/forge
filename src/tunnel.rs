// src/tunnel.rs
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::rustls::pki_types::{DnsName, ServerName};
use tokio_rustls::rustls::{ClientConfig, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const MAX_MESSAGE_SIZE: usize = 65536; // 64KB max message size for better performance
const BUFFER_SIZE: usize = 32768; // 32KB buffer for optimal throughput

pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

#[derive(Debug, Serialize, Deserialize)]
enum TunnelMessage {
    // Control messages
    OpenChannel {
        channel_id: u32,
        direction: TunnelDirection,
        target_host: String,
        target_port: u16,
    },
    CloseChannel {
        channel_id: u32,
    },
    // Data messages
    Data {
        channel_id: u32,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TunnelDirection {
    Forward,
    Reverse,
}

#[allow(dead_code)]
#[derive(Debug)]
struct Channel {
    id: u32,
    direction: TunnelDirection,
    target_host: String,
    target_port: u16,
    bytes_sent: u64,
    bytes_received: u64,
}

pub struct MultiplexedTunnel {
    tls_stream: Box<dyn AsyncStream>,
    channels: HashMap<u32, Channel>,
    next_channel_id: u32,
}

impl MultiplexedTunnel {
    pub fn new(tls_stream: Box<dyn AsyncStream>) -> Self {
        Self {
            tls_stream,
            channels: HashMap::new(),
            next_channel_id: 1,
        }
    }

    pub async fn open_channel(
        &mut self,
        direction: TunnelDirection,
        target_host: String,
        target_port: u16,
    ) -> Result<u32> {
        let channel_id = self.next_channel_id;
        self.next_channel_id += 1;

        let msg = TunnelMessage::OpenChannel {
            channel_id,
            direction,
            target_host: target_host.clone(),
            target_port,
        };

        self.send_message(&msg).await?;

        self.channels.insert(
            channel_id,
            Channel {
                id: channel_id,
                direction,
                target_host,
                target_port,
                bytes_sent: 0,
                bytes_received: 0,
            },
        );

        Ok(channel_id)
    }

    pub async fn close_channel(&mut self, channel_id: u32) -> Result<()> {
        if self.channels.remove(&channel_id).is_some() {
            let msg = TunnelMessage::CloseChannel { channel_id };
            self.send_message(&msg).await?;
        }
        Ok(())
    }

    pub async fn send_data(&mut self, channel_id: u32, data: &[u8]) -> Result<()> {
        let bytes_len = data.len() as u64;

        let msg = TunnelMessage::Data {
            channel_id,
            data: data.to_vec(),
        };

        self.send_message(&msg).await?;

        // Update bytes sent after successful send
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.bytes_sent += bytes_len;
        }

        Ok(())
    }

    async fn send_message(&mut self, msg: &TunnelMessage) -> Result<()> {
        let data = serde_json::to_vec(msg)?;
        let len = data.len() as u32;
        if len > MAX_MESSAGE_SIZE as u32 {
            return Err(anyhow!("Message too large"));
        }

        self.tls_stream.write_u32_le(len).await?;
        self.tls_stream.write_all(&data).await?;
        self.tls_stream.flush().await?;
        Ok(())
    }

    #[allow(private_interfaces)]
    pub async fn receive_message(&mut self) -> Result<TunnelMessage> {
        let len = self.tls_stream.read_u32_le().await? as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message too large"));
        }

        let mut data = vec![0u8; len];
        self.tls_stream.read_exact(&mut data).await?;

        let msg: TunnelMessage = serde_json::from_slice(&data)?;

        if let TunnelMessage::Data {
            channel_id,
            ref data,
        } = msg
        {
            if let Some(channel) = self.channels.get_mut(&channel_id) {
                channel.bytes_received += data.len() as u64;
            }
        }

        Ok(msg)
    }
}

pub struct TunnelManager {
    multiplexer: Arc<Mutex<MultiplexedTunnel>>,
}

impl TunnelManager {
    pub fn new(tls_stream: Box<dyn AsyncStream>) -> Self {
        Self {
            multiplexer: Arc::new(Mutex::new(MultiplexedTunnel::new(tls_stream))),
        }
    }

    pub async fn create_forward_tunnel(
        &self,
        local_port: u16,
        target_host: String,
        target_port: u16,
        protocol: &crate::protocol::TunnelProtocol,
    ) -> Result<()> {
        let mut multiplexer = self.multiplexer.lock().await;
        let channel_id = multiplexer
            .open_channel(TunnelDirection::Forward, target_host, target_port)
            .await?;
        drop(multiplexer); // Release the lock before spawning

        // Start local listener based on protocol
        let multiplexer_clone = self.multiplexer.clone();
        match protocol {
            crate::protocol::TunnelProtocol::Tcp => {
                tokio::spawn(async move {
                    if let Err(e) = handle_local_tcp_listener(local_port, channel_id, multiplexer_clone).await {
                        eprintln!("Forward TCP tunnel error: {}", e);
                    }
                });
            }
            crate::protocol::TunnelProtocol::Udp => {
                tokio::spawn(async move {
                    if let Err(e) = handle_local_udp_listener(local_port, channel_id, multiplexer_clone).await {
                        eprintln!("Forward UDP tunnel error: {}", e);
                    }
                });
            }
            crate::protocol::TunnelProtocol::Socks5 => {
                return Err(anyhow!("SOCKS5 protocol should use separate SOCKS proxy functionality"));
            }
        }

        Ok(())
    }

    pub async fn create_reverse_tunnel(
        &self,
        _remote_port: u16,
        local_host: String,
        local_port: u16,
        _protocol: &crate::protocol::TunnelProtocol,
    ) -> Result<()> {
        let mut multiplexer = self.multiplexer.lock().await;
        multiplexer
            .open_channel(TunnelDirection::Reverse, local_host, local_port)
            .await?;
        Ok(())
    }
}

async fn handle_local_tcp_listener(
    local_port: u16,
    channel_id: u32,
    multiplexer: Arc<Mutex<MultiplexedTunnel>>,
) -> Result<()> {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(format!("127.0.0.1:{}", local_port)).await?;

    loop {
        let (socket, _) = listener.accept().await?;
        let multiplexer = multiplexer.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_local_tcp_connection(socket, channel_id, multiplexer).await {
                eprintln!("TCP connection error: {}", e);
            }
        });
    }
}

async fn handle_local_udp_listener(
    local_port: u16,
    channel_id: u32,
    multiplexer: Arc<Mutex<MultiplexedTunnel>>,
) -> Result<()> {
    let socket = UdpSocket::bind(format!("127.0.0.1:{}", local_port)).await?;
    let mut buf = vec![0u8; BUFFER_SIZE];

    loop {
        let (n, peer_addr) = socket.recv_from(&mut buf).await?;
        
        // For UDP, we need to include the peer address in the data
        // so the remote side knows where to send the response
        let mut udp_packet = Vec::new();
        udp_packet.extend_from_slice(&peer_addr.to_string().as_bytes());
        udp_packet.push(b'\0'); // Null terminator
        udp_packet.extend_from_slice(&buf[..n]);

        let mut multiplexer = multiplexer.lock().await;
        if let Err(e) = multiplexer.send_data(channel_id, &udp_packet).await {
            eprintln!("UDP send error: {}", e);
        }
    }
}

async fn handle_local_tcp_connection(
    mut socket: TcpStream,
    channel_id: u32,
    multiplexer: Arc<Mutex<MultiplexedTunnel>>,
) -> Result<()> {
    let (mut socket_rd, _) = socket.split();
    let mut buf = vec![0u8; BUFFER_SIZE];

    loop {
        let n = socket_rd.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        let mut multiplexer = multiplexer.lock().await;
        multiplexer.send_data(channel_id, &buf[..n]).await?;
    }

    Ok(())
}

// Helper functions for TLS setup
pub async fn create_client_connection(
    addr: &str,
    config: Arc<ClientConfig>,
    server_name: String,
) -> Result<Box<dyn AsyncStream>> {
    let tcp = TcpStream::connect(addr).await?;

    let server_name = if let Ok(ip) = IpAddr::from_str(&server_name) {
        ServerName::IpAddress(ip.into())
    } else {
        // Convert to static string and then get a reference to it
        let static_name = Box::leak(server_name.clone().into_boxed_str());
        let dns_name = DnsName::try_from(&*static_name).map_err(|_| anyhow!("Invalid DNS name"))?;
        ServerName::DnsName(dns_name)
    };

    let connector = TlsConnector::from(config);
    let tls_stream = connector.connect(server_name, tcp).await?;

    Ok(Box::new(tls_stream))
}

pub async fn create_server_connection(
    tcp: TcpStream,
    config: Arc<ServerConfig>,
) -> Result<Box<dyn AsyncStream>> {
    let acceptor = TlsAcceptor::from(config);
    let tls_stream = acceptor.accept(tcp).await?;
    Ok(Box::new(tls_stream))
}
