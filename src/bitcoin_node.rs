use crate::configs::{LocalConfig, TargetNodeConfig};
use crate::message_constructor::{MessageCommand, MessageConstructor};
use crate::message_structures::header::Header;
use crate::sizes::header_sizes;
use crate::sizes::header_sizes::MAGIC_BYTES_SIZE;
use crate::utils::HandshakeError;
use crate::utils::HandshakeError::{FatalError, NonFatalError, WrongMessageError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct BitcoinNode {
    stream: TcpStream,
    msg_ctor: MessageConstructor,
    buf: Vec<u8>,
}

impl BitcoinNode {
    pub async fn new(
        local_config: LocalConfig,
        target_node_config: TargetNodeConfig,
    ) -> Result<Self, HandshakeError> {
        let target_node_addr = format!("{}:{}", target_node_config.ipv4, target_node_config.port);
        let stream = TcpStream::connect(target_node_addr)
            .await
            .or(Err(FatalError))
            .map_err(|e| {
                println!("Failed to connect to target node.");
                e
            })?;

        let msg_ctor = MessageConstructor::new(target_node_config, local_config);

        Ok(Self {
            stream,
            msg_ctor,
            buf: vec![],
        })
    }

    fn clean_used_bytes(&mut self, header: &Header) -> Result<(), HandshakeError> {
        let remove_cnt = self
            .buf
            .len()
            .min(header_sizes::TOTAL_SIZE + header.payload_size as usize);
        self.buf.drain(..remove_cnt);

        Ok(())
    }

    fn clean_bytes(&mut self, num_bytes: usize) -> Result<(), HandshakeError> {
        let remove_cnt = self.buf.len().min(num_bytes);
        self.buf.drain(..remove_cnt);

        Ok(())
    }

    async fn read_from_stream(&mut self) -> Result<(), HandshakeError> {
        // Try reading for several times just in case we start reading from socket before the expected message is sent
        let mut retry = 3;
        let mut n = 0;
        let mut buf = [0u8; 1024];
        while n == 0 && retry > 0 {
            n = self
                .stream
                .read(&mut buf)
                .await
                .or(Err(NonFatalError))
                .map_err(|e| {
                    println!("Failed to read from socket.");
                    e
                })?;
            retry -= 1;
        }

        self.buf.append(&mut buf[..n].to_vec());

        Ok(())
    }

    async fn send_version_msg(&mut self) -> Result<(), HandshakeError> {
        let ver_msg = self
            .msg_ctor
            .get_message(MessageCommand::Version)
            .map_err(|e| {
                println!("Failed to construct version message.");
                e
            })?;

        self.stream
            .write_all(&ver_msg)
            .await
            .or(Err(FatalError))
            .map_err(|e| {
                println!("Failed to send version message.");
                e
            })?;

        Ok(())
    }

    async fn read_version_msg(&mut self) -> Result<i32, HandshakeError> {
        self.read_from_stream().await?;

        let mut num_bytes_used = 0;
        let ver_msg =
            MessageConstructor::version_msg_from_bytes(&self.buf, &mut num_bytes_used);
        if let Err(e) = &ver_msg {
            println!("Failed to read version message.");
            return Err((*e).clone());
        }

        let (_, ver_payload) = ver_msg.unwrap();
        self.clean_bytes(num_bytes_used).or(Err(FatalError))?;

        Ok(ver_payload.version)
    }

    async fn read_verack_msg(&mut self) -> Result<(), HandshakeError> {
        // In case of local version 70016, target node send messages like
        // 'wthidrelay', 'sendaddrv2', etc. between 'version' and 'verack'.
        // Keep reading several times until 'verack' message is read.
        let mut retry = 7;
        self.read_from_stream().await?;

        let mut num_used_bytes = 0;
        let mut msg = MessageConstructor::verack_msg_from_bytes(&self.buf, &mut num_used_bytes);

        while retry > 0 {
            if let Err(e) = &msg {
                if e == &WrongMessageError {
                    retry -= 1;
                    self.clean_bytes(num_used_bytes).or(Err(FatalError))?;
                    num_used_bytes = 0;
                    self.read_from_stream().await?;
                    msg = MessageConstructor::verack_msg_from_bytes(
                        &self.buf,
                        &mut num_used_bytes,
                    );
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        if msg.is_err() {
            println!("Failed to read verack message.");
            return Err(FatalError);
        }

        let verack_header = msg.unwrap();
        self.clean_used_bytes(&verack_header).or(Err(FatalError))?;

        Ok(())
    }

    async fn send_verack_msg(&mut self) -> Result<(), HandshakeError> {
        let verack_msg = self
            .msg_ctor
            .get_message(MessageCommand::VerAck)
            .map_err(|e| {
                println!("Failed to construct verack message.");
                e
            })?;

        self.stream
            .write_all(&verack_msg)
            .await
            .or(Err(FatalError))
            .map_err(|e| {
                println!("Failed to send verack message.");
                e
            })?;

        Ok(())
    }

    pub async fn handshake(&mut self) -> Result<(), HandshakeError> {
        // sending version message
        self.send_version_msg().await?;
        println!("Version message sent.");

        // reading version message
        let target_version = self.read_version_msg().await?;
        println!(
            "Version message received. Target node version: {}.",
            target_version
        );

        // reading verack message
        self.read_verack_msg().await?;
        println!("Verack message received.");

        // sending verack message
        self.send_verack_msg().await?;
        println!("Verack message sent.");

        Ok(())
    }

    /// A test function to make sure that we get 'inv' messages from target node
    pub async fn read_messages_after_handshake(&mut self, n: u32) -> Result<(), HandshakeError> {
        if n == 0 {
            return Ok(());
        }

        println!("Reading next {n} messages.");
        for _ in 0..n {
            // reading next messages
            let mut buf = [0; 500];
            let n = self
                .stream
                .read(&mut buf)
                .await
                .or(Err(FatalError))
                .map_err(|e| {
                    println!("Failed to read from socket.");
                    e
                })?;
            self.buf.append(&mut buf[..n].to_vec());
            if self.buf.is_empty() {
                println!("Empty buffer");
                // sleep(Duration::from_millis(1000)).await;
                continue;
            }
            let mut num_used_bytes = 0;
            let h = MessageConstructor::msg_header_from_bytes(&self.buf, &mut num_used_bytes);
            if let Ok(h) = h {
                self.clean_bytes(num_used_bytes).or(Err(FatalError))?;
                println!("header: {h:?}");
            } else {
                self.clean_bytes(MAGIC_BYTES_SIZE).or(Err(FatalError))?;
                println!("header: None");
            }
        }

        Ok(())
    }
}
