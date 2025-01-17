use anyhow::Result;
use std::net::{TcpStream, UdpSocket};
use std::io::{Read, Write};
use std::thread;

pub enum Tunnel {
    TCP(TcpStream),
    UDP(UdpSocket),
}

impl Tunnel {
    pub fn new_tcp(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Ok(Tunnel::TCP(stream))
    }

    pub fn new_udp(bind_addr: &str, remote_addr: Option<&str>) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)?;
        if let Some(addr) = remote_addr {
            socket.connect(addr)?;
        }
        Ok(Tunnel::UDP(socket))
    }

    pub fn copy_bidirectional(self, other: TcpStream) -> Result<()> {
        match self {
            Tunnel::TCP(stream) => {
                let mut stream_clone = stream.try_clone()?;
                let mut other_clone = other.try_clone()?;
                let mut stream = stream;
                let mut other = other;

                // Thread for stream -> other
                let handle1 = thread::spawn(move || {
                    let mut buf = [0; 16384];
                    loop {
                        match stream_clone.read(&mut buf) {
                            Ok(0) => break, // EOF
                            Ok(n) => {
                                if other.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });

                // Thread for other -> stream
                let handle2 = thread::spawn(move || {
                    let mut buf = [0; 16384];
                    loop {
                        match other_clone.read(&mut buf) {
                            Ok(0) => break, // EOF
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });

                // Wait for both copies to complete
                handle1.join().unwrap();
                handle2.join().unwrap();
                Ok(())
            }
            Tunnel::UDP(_) => Err(anyhow::anyhow!("Cannot use TCP operations on UDP tunnel")),
        }
    }

    pub fn copy_bidirectional_udp(self, other: UdpSocket) -> Result<()> {
        match self {
            Tunnel::UDP(socket) => {
                let socket_clone = socket.try_clone()?;
                let other_clone = other.try_clone()?;

                // Thread for socket -> other
                let handle1 = thread::spawn(move || -> Result<()> {
                    let mut buf = [0; 65507];
                    loop {
                        match socket_clone.recv(&mut buf) {
                            Ok(n) => {
                                if let Err(e) = other.send(&buf[..n]) {
                                    eprintln!("UDP send error: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("UDP receive error: {}", e);
                                break;
                            }
                        }
                    }
                    Ok(())
                });

                // Thread for other -> socket
                let handle2 = thread::spawn(move || -> Result<()> {
                    let mut buf = [0; 65507];
                    loop {
                        match other_clone.recv(&mut buf) {
                            Ok(n) => {
                                if let Err(e) = socket.send(&buf[..n]) {
                                    eprintln!("UDP send error: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("UDP receive error: {}", e);
                                break;
                            }
                        }
                    }
                    Ok(())
                });

                // Wait for both copies to complete
                handle1.join().unwrap()?;
                handle2.join().unwrap()?;
                Ok(())
            }
            Tunnel::TCP(_) => Err(anyhow::anyhow!("Cannot use UDP operations on TCP tunnel")),
        }
    }
}