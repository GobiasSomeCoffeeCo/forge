// src/protocol.rs
#![allow(dead_code)]
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TunnelDirection {
    Forward,  // -L style: local port -> remote target
    Reverse,  // -R style: remote port <- local target
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Command {
    Register { client_id: String },
    CreateTunnel { 
        local_port: u16,
        target_host: String,
        target_port: u16,
        direction: TunnelDirection,
    },
    ModifyTunnel {
        local_port: u16,
        new_target_host: String,
        new_target_port: u16,
    },
    CloseTunnel {
        local_port: u16,
    },
    ListTunnels,
    OpenTunnel { port: u16 }, // Keep this temporarily for backward compatibility
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelInfo {
    pub local_port: u16,
    pub target_host: String,
    pub target_port: u16,
    pub direction: TunnelDirection,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    TunnelList(Vec<TunnelInfo>),
    Error(String),
}