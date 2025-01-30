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
    },
    ModifyTunnel {
        old_local_port: u16,     // Current local port
        new_local_port: u16,     // New local port to listen on
        new_target_host: String, // New target IP/hostname
        new_target_port: u16,    // New target port
    },
    CloseTunnel {
        local_port: u16,
    },
    ListTunnels,
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
