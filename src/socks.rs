// src/socks.rs - SOCKS5 proxy implementation for network tunneling
use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_CONNECT: u8 = 0x01;
const SOCKS5_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS5_IPV4: u8 = 0x01;
const SOCKS5_DOMAIN: u8 = 0x03;
const SOCKS5_IPV6: u8 = 0x04;

#[derive(Debug, Clone)]
pub struct SocksConfig {
    pub bind_addr: SocketAddr,
    pub timeout: Duration,
    pub enable_udp: bool,
}

impl Default for SocksConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:1080".parse().unwrap(),
            timeout: Duration::from_secs(10),
            enable_udp: true,
        }
    }
}

pub struct SocksProxy {
    config: SocksConfig,
    listener: Option<TcpListener>,
}

impl SocksProxy {
    pub fn new(config: SocksConfig) -> Self {
        Self {
            config,
            listener: None,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.bind_addr).await?;
        println!("SOCKS5 proxy listening on {}", self.config.bind_addr);
        
        self.listener = Some(listener);
        
        loop {
            let listener = self.listener.as_ref().unwrap();
            let (stream, peer_addr) = listener.accept().await?;
            println!("SOCKS connection from {}", peer_addr);
            
            let config = self.config.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_socks_connection(stream, config).await {
                    eprintln!("SOCKS connection error: {}", e);
                }
            });
        }
    }

}

async fn handle_socks_connection(mut stream: TcpStream, config: SocksConfig) -> Result<()> {
    // SOCKS5 authentication negotiation
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).await?;
    
    if n < 3 || buf[0] != SOCKS5_VERSION {
        return Err(anyhow!("Invalid SOCKS5 version"));
    }

    let nmethods = buf[1] as usize;
    if n < 2 + nmethods {
        return Err(anyhow!("Invalid authentication methods"));
    }

    // Send no authentication required
    stream.write_all(&[SOCKS5_VERSION, SOCKS5_NO_AUTH]).await?;

    // Read connection request
    let n = stream.read(&mut buf).await?;
    if n < 4 || buf[0] != SOCKS5_VERSION {
        return Err(anyhow!("Invalid SOCKS5 request"));
    }

    let cmd = buf[1];
    let atyp = buf[3];

    let (target_addr, target_port) = match atyp {
        SOCKS5_IPV4 => {
            if n < 10 {
                return Err(anyhow!("Invalid IPv4 request"));
            }
            let addr = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (IpAddr::V4(addr).to_string(), port)
        }
        SOCKS5_IPV6 => {
            if n < 22 {
                return Err(anyhow!("Invalid IPv6 request"));
            }
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&buf[4..20]);
            let addr = Ipv6Addr::from(addr_bytes);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (IpAddr::V6(addr).to_string(), port)
        }
        SOCKS5_DOMAIN => {
            if n < 5 {
                return Err(anyhow!("Invalid domain request"));
            }
            let domain_len = buf[4] as usize;
            if n < 5 + domain_len + 2 {
                return Err(anyhow!("Incomplete domain request"));
            }
            let domain = String::from_utf8(buf[5..5 + domain_len].to_vec())?;
            let port = u16::from_be_bytes([buf[5 + domain_len], buf[5 + domain_len + 1]]);
            (domain, port)
        }
        _ => return Err(anyhow!("Unsupported address type")),
    };

    match cmd {
        SOCKS5_CONNECT => {
            handle_connect(stream, &target_addr, target_port, config.timeout).await
        }
        SOCKS5_UDP_ASSOCIATE if config.enable_udp => {
            handle_udp_associate(stream, config).await
        }
        _ => {
            // Send command not supported
            stream.write_all(&[SOCKS5_VERSION, 0x07, 0x00, SOCKS5_IPV4, 0, 0, 0, 0, 0, 0]).await?;
            Err(anyhow!("Unsupported SOCKS command"))
        }
    }
}

async fn handle_connect(mut client: TcpStream, target_addr: &str, target_port: u16, timeout_duration: Duration) -> Result<()> {
    let target = format!("{}:{}", target_addr, target_port);
    
    let target_stream = match timeout(timeout_duration, TcpStream::connect(&target)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => {
            // Connection failed - send SOCKS5 error response
            client.write_all(&[SOCKS5_VERSION, 0x05, 0x00, SOCKS5_IPV4, 0, 0, 0, 0, 0, 0]).await?;
            return Err(anyhow!("Connection to target failed"));
        }
        Err(_) => {
            // Timeout - send SOCKS5 error response  
            client.write_all(&[SOCKS5_VERSION, 0x04, 0x00, SOCKS5_IPV4, 0, 0, 0, 0, 0, 0]).await?;
            return Err(anyhow!("Connection timeout"));
        }
    };

    // Send success response
    client.write_all(&[SOCKS5_VERSION, 0x00, 0x00, SOCKS5_IPV4, 127, 0, 0, 1, 0, 0]).await?;

    // Start proxying data
    proxy_data(client, target_stream).await
}

async fn handle_udp_associate(mut client: TcpStream, _config: SocksConfig) -> Result<()> {
    // Create UDP socket for association
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = udp_socket.local_addr()?;
    
    // Send UDP associate response
    let port_bytes = local_addr.port().to_be_bytes();
    client.write_all(&[
        SOCKS5_VERSION, 0x00, 0x00, SOCKS5_IPV4, 
        127, 0, 0, 1, port_bytes[0], port_bytes[1]
    ]).await?;

    // Handle UDP relay (simplified implementation)
    let mut buf = [0u8; 65536];
    loop {
        tokio::select! {
            result = udp_socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, peer)) => {
                        // Parse UDP request and forward (implementation needed)
                        println!("UDP packet from {}: {} bytes", peer, n);
                    }
                    Err(e) => {
                        eprintln!("UDP recv error: {}", e);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(300)) => {
                // Timeout UDP association
                break;
            }
        }
    }

    Ok(())
}

async fn proxy_data(client: TcpStream, target: TcpStream) -> Result<()> {
    let (mut client_rd, mut client_wr) = client.into_split();
    let (mut target_rd, mut target_wr) = target.into_split();

    let client_to_target = async {
        let mut buf = [0u8; 32768]; // Larger buffer for better performance
        loop {
            let n = client_rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            target_wr.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let target_to_client = async {
        let mut buf = [0u8; 32768]; // Larger buffer for better performance
        loop {
            let n = target_rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_wr.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(client_to_target, target_to_client)?;
    Ok(())
}

