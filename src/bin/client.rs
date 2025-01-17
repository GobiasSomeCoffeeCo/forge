// src/bin/client.rs
use anyhow::Result;
use clap::Parser;
use std::net::TcpStream;
use std::io::{Read, Write};
use forge::protocol::{Command, Response, TunnelSpec};

#[derive(Parser)]
#[command(about = "Tunnel client")]
struct Args {
    /// Server address
    #[arg(short, long)]
    server: String,

    /// Remote specification in format: [r:][udp:]local_host:local_port:remote_host:remote_port
    #[arg(short = 'R', long = "remote")]
    remote: String,

    /// Client ID (optional, will use process ID if not specified)
    #[arg(short, long)]
    id: Option<String>,
}

struct Client {
    stream: TcpStream,
    id: String,
}

impl Client {
    fn new(addr: &str, id: String) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Ok(Self { stream, id })
    }

    fn register(&mut self) -> Result<()> {
        let cmd = Command::Register {
            client_id: self.id.clone(),
        };
        
        let data = serde_json::to_vec(&cmd)?;
        self.stream.write_all(&data)?;

        // Wait for response
        let mut buffer = vec![0; 1024];
        self.stream.read(&mut buffer)?;
        
        match serde_json::from_slice(&buffer)? {
            Response::Ok => {
                println!("Registered with server");
                Ok(())
            }
            Response::Error(e) => {
                anyhow::bail!("Registration failed: {}", e)
            }
        }
    }

    fn open_tunnel(&mut self, spec: TunnelSpec) -> Result<()> {
        let cmd = Command::OpenTunnel {
            spec,
            client_id: self.id.clone(),
        };
        
        let data = serde_json::to_vec(&cmd)?;
        self.stream.write_all(&data)?;

        // Wait for response
        let mut buffer = vec![0; 1024];
        self.stream.read(&mut buffer)?;
        
        match serde_json::from_slice(&buffer)? {
            Response::Ok => {
                println!("Tunnel opened successfully");
                Ok(())
            }
            Response::Error(e) => {
                anyhow::bail!("Failed to open tunnel: {}", e)
            }
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let id = args.id.unwrap_or_else(|| format!("client-{}", std::process::id()));
    
    let mut client = Client::new(&args.server, id)?;
    println!("Connecting to server at {}", args.server);
    
    client.register()?;
    
    let spec = TunnelSpec::parse(&args.remote)?;
    client.open_tunnel(spec)?;
    
    println!("Client running, press Ctrl+C to exit");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}