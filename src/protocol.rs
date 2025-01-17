use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TunnelType {
    TCP,
    UDP,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelSpec {
    pub local_host: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub reverse: bool,
    pub tunnel_type: TunnelType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    // Client registration
    Register { 
        client_id: String,
    },
    
    // Tunnel management
    OpenTunnel { 
        spec: TunnelSpec,
        client_id: String,
    },
    CloseTunnel { 
        port: u16,
        client_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Error(String),
}

impl TunnelSpec {
    pub fn parse(spec: &str) -> anyhow::Result<Self> {
        let reverse = spec.starts_with("r:");
        let is_udp = spec.starts_with("udp:");
        let spec = spec.trim_start_matches("r:")
                      .trim_start_matches("udp:");
        
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() != 4 {
            anyhow::bail!("Invalid tunnel specification. Format: [r:][udp:]local_host:local_port:remote_host:remote_port");
        }

        Ok(Self {
            reverse,
            local_host: parts[0].to_string(),
            local_port: parts[1].parse()?,
            remote_host: parts[2].to_string(),
            remote_port: parts[3].parse()?,
            tunnel_type: if is_udp { TunnelType::UDP } else { TunnelType::TCP },
        })
    }
}