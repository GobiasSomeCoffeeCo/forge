// src/protocol.rs
#![allow(dead_code)]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TunnelDirection {
    Forward,
    Reverse,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Command {
    Register {
        client_id: String,
    },
    CreateTunnel {
        local_port: u16,
        target_host: String,
        target_port: u16,
        direction: TunnelDirection,
        protocol: TunnelProtocol,
    },
    ModifyTunnel {
        old_local_port: u16,    
        new_local_port: u16,    
        new_target_host: String,
        new_target_port: u16,   
    },
    CloseTunnel {
        local_port: u16,
    },
    ListTunnels,
    StartSocksProxy {
        bind_port: u16,
        timeout: u64,
    },
    StopSocksProxy,
    ScanPorts {
        target: String,
        ports: Vec<u16>,
        timeout_ms: u64,
    },
    StartSocksTunnel {
        local_port: u16,
        timeout: u64,
    },
    StopSocksTunnel {
        local_port: u16,
    },
    SocksData {
        local_port: u16,
        connection_id: u32,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TunnelProtocol {
    Tcp,
    Udp,
    Socks5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelInfo {
    pub local_port: u16,
    pub target_host: String,
    pub target_port: u16,
    pub direction: TunnelDirection,
    pub protocol: TunnelProtocol,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connections_active: u32,
    pub connections_total: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    TunnelList(Vec<TunnelInfo>),
    Error(String),
    SocksData {
        local_port: u16,
        connection_id: u32,
        data: Vec<u8>,
    },
}
