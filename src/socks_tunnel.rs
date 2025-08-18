// src/socks_tunnel.rs - SOCKS proxy that tunnels through TLS control channel
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use crate::protocol::{Command, Response};

#[derive(Clone)]
pub struct SocksTunnelProxy {
    local_port: u16,
    timeout: u64,
    connections: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    next_connection_id: Arc<Mutex<u32>>,
    command_sender: mpsc::Sender<Command>,
    data_receiver: Arc<Mutex<mpsc::Receiver<Response>>>,
}

impl SocksTunnelProxy {
    pub fn new(
        local_port: u16,
        timeout: u64,
        command_sender: mpsc::Sender<Command>,
        data_receiver: mpsc::Receiver<Response>,
    ) -> Self {
        Self {
            local_port,
            timeout,
            connections: Arc::new(Mutex::new(HashMap::new())),
            next_connection_id: Arc::new(Mutex::new(1)),
            command_sender,
            data_receiver: Arc::new(Mutex::new(data_receiver)),
        }
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.local_port)).await?;
        println!("SOCKS tunnel proxy listening on 127.0.0.1:{}", self.local_port);

        // Start data receiver task
        let connections_clone = self.connections.clone();
        let data_receiver = self.data_receiver.clone();
        tokio::spawn(async move {
            Self::handle_data_responses(connections_clone, data_receiver).await;
        });

        // Send start tunnel command to client
        let start_cmd = Command::StartSocksTunnel {
            local_port: self.local_port,
            timeout: self.timeout,
        };
        
        if let Err(e) = self.command_sender.send(start_cmd).await {
            return Err(anyhow!("Failed to send start command to client: {}", e));
        }

        // Accept SOCKS connections
        loop {
            let (socket, addr) = listener.accept().await?;
            println!("New SOCKS connection from {}", addr);

            let connection_id = {
                let mut next_id = self.next_connection_id.lock().await;
                let id = *next_id;
                *next_id += 1;
                id
            };

            let connections = self.connections.clone();
            let command_sender = self.command_sender.clone();
            let local_port = self.local_port;

            tokio::spawn(async move {
                if let Err(e) = Self::handle_socks_connection(
                    socket,
                    connection_id,
                    local_port,
                    connections,
                    command_sender,
                ).await {
                    eprintln!("SOCKS connection error: {}", e);
                }
            });
        }
    }

    async fn handle_socks_connection(
        socket: TcpStream,
        connection_id: u32,
        local_port: u16,
        connections: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
        command_sender: mpsc::Sender<Command>,
    ) -> Result<()> {
        // Create channel for this connection's responses
        let (response_tx, mut response_rx) = mpsc::channel::<Vec<u8>>(100);
        
        // Register this connection
        {
            let mut conns = connections.lock().await;
            conns.insert(connection_id, response_tx);
        }

        // Handle bidirectional data flow
        let (socket_read, socket_write) = socket.into_split();
        
        // Task to read from client and send to TLS channel
        let command_sender_clone = command_sender.clone();
        let read_task = tokio::spawn(async move {
            let mut socket_read = socket_read;
            let mut buf = vec![0u8; 8192];
            loop {
                match socket_read.read(&mut buf).await {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        let data_cmd = Command::SocksData {
                            local_port,
                            connection_id,
                            data: buf[..n].to_vec(),
                        };
                        
                        if let Err(e) = command_sender_clone.send(data_cmd).await {
                            eprintln!("Failed to send data to client: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Socket read error: {}", e);
                        break;
                    }
                }
            }
        });

        // Task to read responses and send to socket
        let write_task = tokio::spawn(async move {
            let mut socket_write = socket_write;
            while let Some(data) = response_rx.recv().await {
                if let Err(e) = socket_write.write_all(&data).await {
                    eprintln!("Socket write error: {}", e);
                    break;
                }
            }
        });

        // Wait for either task to complete
        tokio::select! {
            _ = read_task => {},
            _ = write_task => {},
        }

        // Clean up connection
        {
            let mut conns = connections.lock().await;
            conns.remove(&connection_id);
        }

        println!("SOCKS connection {} closed", connection_id);
        Ok(())
    }

    async fn handle_data_responses(
        connections: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
        data_receiver: Arc<Mutex<mpsc::Receiver<Response>>>,
    ) {
        let mut receiver = data_receiver.lock().await;
        
        while let Some(response) = receiver.recv().await {
            if let Response::SocksData { local_port: _, connection_id, data } = response {
                let conns = connections.lock().await;
                if let Some(sender) = conns.get(&connection_id) {
                    if let Err(e) = sender.send(data).await {
                        eprintln!("Failed to send data to connection {}: {}", connection_id, e);
                    }
                }
            }
        }
    }

    pub async fn stop(&self) -> Result<()> {
        let stop_cmd = Command::StopSocksTunnel {
            local_port: self.local_port,
        };
        
        self.command_sender.send(stop_cmd).await?;
        
        // Clear all connections
        let mut conns = self.connections.lock().await;
        conns.clear();
        
        println!("SOCKS tunnel proxy on port {} stopped", self.local_port);
        Ok(())
    }
}