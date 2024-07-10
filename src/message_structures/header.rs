use crate::message_constructor::{MessageCommand, MAGIC_BYTES};
use crate::sizes::header_sizes;
use crate::utils::HandshakeError::FatalError;
use crate::utils::{
    FromBytes, FromLittleEndian, HandshakeError, ToBytes, ToLittleEndian,
};
use sha2::{Digest, Sha256};

static HEADER_CHECKSUM_BYTES_SIZE: usize = 4;

#[derive(Eq, PartialEq, Debug)]
pub struct Header {
    pub command: MessageCommand,
    pub payload_size: i32,
    pub checksum: Vec<u8>,
}

impl Header {
    pub fn get_checksum(payload: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let result = &hasher.finalize()[..];
        let mut hasher = Sha256::new();
        hasher.update(result);

        hasher.finalize()[..HEADER_CHECKSUM_BYTES_SIZE].to_vec()
    }

    pub fn new(command: MessageCommand, payload: &Vec<u8>) -> Self {
        let checksum = Self::get_checksum(payload);

        Self {
            command,
            payload_size: payload.len() as i32,
            checksum,
        }
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, HandshakeError> {
        let mut res = vec![];
        res.append(&mut MAGIC_BYTES.to_vec());
        res.append(
            &mut self
                .command
                .to_string()
                .to_bytes(Some(header_sizes::COMMAND_SIZE))?,
        );
        res.append(&mut self.payload_size.to_little_endian()?);
        res.append(&mut self.checksum.clone());

        Ok(res)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HandshakeError> {
        if bytes.len() != header_sizes::TOTAL_SIZE {
            println!(
                "Failed to construct header. Waiting for {} bytes, got {} bytes",
                header_sizes::TOTAL_SIZE,
                bytes.len()
            );
            return Err(FatalError);
        }
        // verify magic bytes
        let magic_bytes_end = header_sizes::MAGIC_BYTES_SIZE;
        let magic_byes = &bytes[..magic_bytes_end];
        if magic_byes != MAGIC_BYTES {
            println!("Failed to construct header. No magic bytes.");
            return Err(FatalError);
        }

        // read command
        let command_end = magic_bytes_end + header_sizes::COMMAND_SIZE;
        let command = String::from_bytes(&bytes[magic_bytes_end..command_end])
            .map_err(|e| {
                println!("Failed to construct header. Problem when reading command.");
                e
            })?
            .into();

        // read payload size
        let payload_length_end = command_end + header_sizes::PAYLOAD_LENGTH_SIZE;
        let payload_length = i32::from_little_endian(&bytes[command_end..payload_length_end])
            .map_err(|e| {
                println!("Failed to construct header. Couldn't read payload size.");
                e
            })?;

        // read checksum
        let checksum_end = payload_length_end + header_sizes::CHECKSUM_SIZE;
        let checksum = bytes[payload_length_end..checksum_end].to_vec();

        Ok(Self {
            command,
            payload_size: payload_length,
            checksum,
        })
    }
}

#[cfg(test)]
mod header_tests {
    use crate::message_constructor::MessageCommand;
    use crate::message_structures::header::{Header, MAGIC_BYTES};
    use crate::message_structures::network_address::NetworkAddress;
    use crate::message_structures::version::VersionPayload;
    use chrono::{TimeZone, Utc};

    fn get_test_version_payload() -> VersionPayload {
        VersionPayload {
            version: 60002,
            services: 1,
            timestamp: Utc
                .with_ymd_and_hms(2012, 12, 18, 18, 12, 33)
                .unwrap()
                .timestamp(), // Mon Dec 20 21:50:14 EST 2010
            addr_recv: NetworkAddress::new("0.0.0.0".to_string(), 0, Some(1)),
            addr_from: NetworkAddress::new("0.0.0.0".to_string(), 0, Some(1)),
            nonce: 7284544412836900411,
            user_agent: "/Satoshi:0.7.2/".to_string(),
            last_block: 212672,
            relay: false,
        }
    }

    fn get_test_header_bytes() -> Vec<u8> {
        let command_bytes: [u8; 12] = [
            0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let payload_size_bytes: [u8; 4] = [0x64, 0x00, 0x00, 0x00];
        // According to the example from the documentation, checksum must be [0x35, 0x8D, 0x49, 0x32],
        // but I'm getting another result which seems is correct as bitcoin node doesn't consider it as wrong.
        let checksum_bytes: [u8; 4] = [0x3B, 0x64, 0x8D, 0x5A];

        let mut bytes = vec![];
        bytes.extend(MAGIC_BYTES);
        bytes.extend(command_bytes);
        bytes.extend(payload_size_bytes);
        bytes.extend(checksum_bytes);

        bytes
    }

    #[test]
    fn header_to_bytes_test() {
        let ver_payload_bytes = get_test_version_payload().as_bytes().unwrap();
        let ver_header = Header::new(MessageCommand::Version, &ver_payload_bytes);
        let ver_header_bytes = ver_header.as_bytes();

        let should_be = get_test_header_bytes();

        assert_eq!(ver_header_bytes, Ok(should_be));
    }

    #[test]
    fn header_from_bytes_test() {
        let bytes = get_test_header_bytes();
        let header = Header::from_bytes(&bytes);

        let should_be = Header {
            command: MessageCommand::Version,
            payload_size: 100,
            checksum: bytes[bytes.len() - 4..].to_vec(),
        };

        assert_eq!(header, Ok(should_be));
    }
}
