use crate::configs::{LocalConfig, TargetNodeConfig};
use crate::message_structures::header::Header;
use crate::message_structures::version::VersionPayload;
use crate::sizes::header_sizes;
use crate::sizes::header_sizes::MAGIC_BYTES_SIZE;
use crate::utils::HandshakeError::{FatalError, NotSupportedError, WrongMessageError};
use crate::utils::HandshakeError;
use serde::Serialize;
use std::fmt;

pub static MAGIC_BYTES: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

#[derive(Serialize, Debug, PartialEq, Eq)]
pub enum MessageCommand {
    Version,
    VerAck,
    // For commands that aren't currently supported as they are not necessary for handshake
    Other(String),
}

impl fmt::Display for MessageCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            MessageCommand::Version => "version",
            MessageCommand::VerAck => "verack",
            MessageCommand::Other(command) => command,
        };
        write!(f, "{}", s)
    }
}

impl From<String> for MessageCommand {
    fn from(value: String) -> Self {
        match value.as_str() {
            "version" => MessageCommand::Version,
            "verack" => MessageCommand::VerAck,
            _ => MessageCommand::Other(value),
        }
    }
}

pub struct MessageConstructor {
    target_node_config: TargetNodeConfig,
    local_config: LocalConfig,
}

impl MessageConstructor {
    pub fn new(target_node_config: TargetNodeConfig, local_config: LocalConfig) -> Self {
        Self {
            target_node_config,
            local_config,
        }
    }

    pub fn get_version_msg_payload(&self) -> Result<Vec<u8>, HandshakeError> {
        VersionPayload::new(&self.target_node_config, &self.local_config).as_bytes()
    }

    pub fn get_verack_msg_payload(&self) -> Result<Vec<u8>, HandshakeError> {
        Ok(vec![])
    }

    pub fn get_msg_header(
        &self,
        command: MessageCommand,
        payload: &Vec<u8>,
    ) -> Result<Vec<u8>, HandshakeError> {
        Header::new(command, payload).as_bytes()
    }

    pub fn get_message(&self, command: MessageCommand) -> Result<Vec<u8>, HandshakeError> {
        let mut payload = match command {
            MessageCommand::Version => self.get_version_msg_payload(),
            MessageCommand::VerAck => self.get_verack_msg_payload(),
            _ => Err(NotSupportedError),
        }?;

        let mut bytes = self.get_msg_header(command, &payload)?;
        bytes.append(&mut payload);

        Ok(bytes)
    }

    fn find_msg_start(bytes: &Vec<u8>) -> i32 {
        let start_idx = -1;
        for i in 0..bytes.len() {
            let mut bytes_i = i;
            let mut m_bytes_i = 0;
            let start_idx = loop {
                if bytes[bytes_i] != MAGIC_BYTES[m_bytes_i] {
                    break -1;
                }

                bytes_i += 1;
                m_bytes_i += 1;

                if m_bytes_i == MAGIC_BYTES_SIZE {
                    break i as i32;
                } else if bytes_i == bytes.len() {
                    break -1;
                }
            };

            if start_idx >= 0 {
                return start_idx;
            }
        }

        start_idx
    }

    pub fn msg_header_from_bytes(
        bytes: &Vec<u8>,
        num_bytes_read: &mut usize,
    ) -> Result<Header, HandshakeError> {
        let msg_start = MessageConstructor::find_msg_start(bytes);
        if msg_start < 0 {
            println!("Failed to construct message header. No Magic bytes.");
            return Err(FatalError);
        }

        let bytes = &bytes[msg_start as usize..];

        if bytes.len() < header_sizes::TOTAL_SIZE {
            println!(
                "Failed to construct message header. Bytes size {} is less than header size {}.",
                bytes.len(),
                header_sizes::TOTAL_SIZE
            );
            return Err(FatalError);
        }

        let header = Header::from_bytes(&bytes[..header_sizes::TOTAL_SIZE])?;
        *num_bytes_read = msg_start as usize + header_sizes::TOTAL_SIZE;

        Ok(header)
    }

    /// Finds the start of the massage (magic bytes) and tries to construct version message from the bytes.
    pub fn version_msg_from_bytes(
        bytes: &Vec<u8>,
        num_bytes_read: &mut usize,
    ) -> Result<(Header, VersionPayload), HandshakeError> {
        let header = MessageConstructor::msg_header_from_bytes(bytes, num_bytes_read)?;
        if header.command != MessageCommand::Version {
            println!("Failed to construct version message. Not a version header.");
            return Err(WrongMessageError);
        }

        if bytes.len() < header_sizes::TOTAL_SIZE + header.payload_size as usize {
            println!(
                "Failed to construct version message. Bytes size {} is less than header size {} + payload size {}.",
                bytes.len(),
                header_sizes::TOTAL_SIZE,
                header.payload_size
            );
            return Err(FatalError);
        }

        let payload_end = header_sizes::TOTAL_SIZE + header.payload_size as usize;
        let payload_bytes = &bytes[header_sizes::TOTAL_SIZE..payload_end];

        let checksum = Header::get_checksum(payload_bytes);
        if checksum != header.checksum {
            println!("Failed to parse version message. Wrong checksum.");
            return Err(FatalError);
        }

        let payload = VersionPayload::from_bytes(payload_bytes)?;

        *num_bytes_read += header.payload_size as usize;

        Ok((header, payload))
    }

    pub fn verack_msg_from_bytes(
        bytes: &Vec<u8>,
        num_bytes_read: &mut usize,
    ) -> Result<Header, HandshakeError> {
        let header = MessageConstructor::msg_header_from_bytes(bytes, num_bytes_read)?;
        if header.command != MessageCommand::VerAck {
            println!("Failed to construct verack message. Not a verack header.");
            println!("Message command in header: {}", header.command);
            return Err(WrongMessageError);
        }

        Ok(header)
    }
}
