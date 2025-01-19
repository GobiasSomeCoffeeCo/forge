// src/tunnel.rs
use anyhow::{anyhow, Context, Result};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::rustls::{ClientConfig, ServerConfig};
use tokio_rustls::rustls::pki_types::{DnsName, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use std::sync::Arc;
use std::net::IpAddr;
use std::str::FromStr;

// Make the trait and impl fully public
pub trait AsyncStream: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncStream for T {}

pub enum Tunnel {
    TCP(TcpStream),
    TLS(Box<dyn AsyncStream + Unpin>),
    UDP(UdpSocket),
}

impl Tunnel {
    pub async fn new_tcp(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Tunnel::TCP(stream))
    }

    pub async fn new_tls_client(
        addr: &str, 
        config: Arc<ClientConfig>,
        server_name: String,
    ) -> Result<Self> {
        // Connect TCP first
        let tcp = TcpStream::connect(addr)
            .await
            .context("Failed to establish TCP connection")?;

        // Convert server name to a static reference and parse as either IP or DNS name
        let sni = Box::leak(server_name.into_boxed_str()) as &str;
        let server_name = if let Ok(ip) = IpAddr::from_str(sni) {
            ServerName::IpAddress(ip.into())
        } else {
            let dns_name = DnsName::try_from(sni)
                .map_err(|_| anyhow!("Invalid server name (neither IP address nor valid DNS name): {}", sni))?;
            ServerName::DnsName(dns_name)
        };
        
        // Upgrade to TLS
        let connector = TlsConnector::from(config);
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .context("TLS handshake failed")?;

        Ok(Tunnel::TLS(Box::new(tls_stream)))
    }

    pub async fn new_tls_server(
        tcp: TcpStream,
        config: Arc<ServerConfig>,
    ) -> Result<Self> {
        // Upgrade incoming TCP connection to TLS
        let acceptor = TlsAcceptor::from(config);
        let tls_stream = acceptor
            .accept(tcp)
            .await
            .context("TLS handshake failed")?;

        Ok(Tunnel::TLS(Box::new(tls_stream)))
    }

    pub async fn new_udp(bind_addr: &str, remote_addr: Option<&str>) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        if let Some(addr) = remote_addr {
            socket.connect(addr).await?;
        }
        Ok(Tunnel::UDP(socket))
    }

    /// Forward traffic from self to remote_tunnel
    pub async fn forward_to(&mut self, remote_tunnel: &mut Tunnel) -> Result<()> {
        match (self, remote_tunnel) {
            (Tunnel::TCP(local), Tunnel::TCP(remote)) => {
                io::copy_bidirectional(local, remote).await?;
            }
            (Tunnel::TLS(local), Tunnel::TLS(remote)) => {
                io::copy_bidirectional(local.as_mut(), remote.as_mut()).await?;
            }
            (Tunnel::UDP(local), Tunnel::UDP(remote)) => {
                const BUFFER_SIZE: usize = 65536;
                let mut buf = vec![0u8; BUFFER_SIZE];
                
                loop {
                    let n = local.recv(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    remote.send(&buf[..n]).await?;
                }
            }
            _ => {
                return Err(anyhow!("Mismatched tunnel types for forwarding"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_rustls::rustls::{RootCertStore, ClientConfig};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_tls_tunnel_dns() -> Result<()> {
        let client_config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();

        let _tunnel = Tunnel::new_tls_client(
            "localhost:8443",
            Arc::new(client_config),
            "localhost".to_string(),
        ).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_tls_tunnel_ip() -> Result<()> {
        let client_config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();

        let _tunnel = Tunnel::new_tls_client(
            "127.0.0.1:8443",
            Arc::new(client_config),
            "127.0.0.1".to_string(),
        ).await?;

        Ok(())
    }
}