// src/bin/server.rs
use anyhow::Result;
use clap::Parser;
use forge::protocol::{Command, Response, TunnelSpec};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Parser)]
#[command(about = "Tunnel server")]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    addr: String,
}

struct Client {
    id: String,
    stream: TcpStream,
    tunnels: HashMap<u16, TunnelSpec>,
}

struct Server {
    clients: Arc<Mutex<HashMap<String, Client>>>,
}

impl Server {
    fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn run(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr)?;
        println!("Server listening on {}", addr);

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let clients = Arc::clone(&self.clients);
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_client(stream, clients) {
                            eprintln!("Client error: {}", e);
                        }
                    });
                }
                Err(e) => eprintln!("Accept error: {}", e),
            }
        }
        Ok(())
    }

    fn handle_client(
        stream: TcpStream,
        clients: Arc<Mutex<HashMap<String, Client>>>,
    ) -> Result<()> {
        let mut stream = stream;
        let mut buffer = vec![0; 4096];

        // Handle initial registration
        match stream.read(&mut buffer) {
            Ok(n) if n > 0 => {
                if let Ok(cmd) = serde_json::from_slice(&buffer[..n]) {
                    match cmd {
                        Command::Register { client_id } => {
                            let response = Response::Ok;
                            stream.write_all(&serde_json::to_vec(&response)?)?;

                            let client = Client {
                                id: client_id.clone(),
                                stream: stream.try_clone()?,
                                tunnels: HashMap::new(),
                            };
                            clients.lock().unwrap().insert(client_id.clone(), client);
                            println!("Client registered: {}", client_id);
                        }
                        _ => return Ok(()),
                    }
                }
            }
            _ => return Ok(()),
        }

        // Handle ongoing commands
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    if let Ok(cmd) = serde_json::from_slice(&buffer[..n]) {
                        match cmd {
                            Command::OpenTunnel { spec, client_id } => {
                                println!(
                                    "Opening tunnel for client {}: {}:{} -> {}:{}",
                                    client_id,
                                    spec.local_host,
                                    spec.local_port,
                                    spec.remote_host,
                                    spec.remote_port
                                );

                                if let Some(mut guard) = clients.lock().ok() {
                                    if let Some(client) = guard.get_mut(&client_id) {
                                        client.tunnels.insert(spec.local_port, spec);
                                        let response = Response::Ok;
                                        stream.write_all(&serde_json::to_vec(&response)?)?;
                                    }
                                }
                            }
                            Command::CloseTunnel { port, client_id } => {
                                if let Some(mut guard) = clients.lock().ok() {
                                    if let Some(client) = guard.get_mut(&client_id) {
                                        client.tunnels.remove(&port);
                                        let response = Response::Ok;
                                        stream.write_all(&serde_json::to_vec(&response)?)?;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(_) => break,
            }
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let server = Server::new();
    server.run(&args.addr)
}
