use crate::configs::{LocalConfig, TargetNodeConfig};
use crate::message_structures::network_address::NetworkAddress;
use crate::sizes::version_payload_sizes;
use crate::utils::HandshakeError::FatalError;
use crate::utils::{FromLittleEndian, HandshakeError, ToBytes, ToLittleEndian};
use chrono::Utc;

#[derive(Eq, PartialEq, Debug)]
pub struct VersionPayload {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub addr_recv: NetworkAddress,
    pub addr_from: NetworkAddress,
    pub nonce: u64,
    pub user_agent: String,
    pub last_block: i32,
}

impl VersionPayload {
    pub fn new(remote_config: &TargetNodeConfig, local_config: &LocalConfig) -> Self {
        Self {
            version: local_config.version,
            services: 0,
            timestamp: Utc::now().timestamp(),
            addr_recv: NetworkAddress::new(remote_config.ipv4.to_owned(), remote_config.port, None),
            addr_from: NetworkAddress::new(
                local_config.ipv4.to_owned(),
                local_config.port,
                Some(local_config.services),
            ),
            nonce: 0,
            user_agent: "".to_string(),
            last_block: 0,
        }
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, HandshakeError> {
        let mut res = vec![];
        res.append(&mut self.version.to_little_endian()?);
        res.append(&mut self.services.to_little_endian()?);
        res.append(&mut self.timestamp.to_little_endian()?);
        res.append(&mut self.addr_recv.as_bytes()?);
        res.append(&mut self.addr_from.as_bytes()?);
        res.append(&mut self.nonce.to_little_endian()?);
        res.append(&mut self.user_agent.to_bytes(None)?);
        res.append(&mut self.last_block.to_little_endian()?);

        Ok(res)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HandshakeError> {
        if bytes.len() < version_payload_sizes::MIN_SIZE {
            println!(
                "Failed to construct version payload. Waiting for minimum {} bytes, got {} bytes",
                version_payload_sizes::MIN_SIZE,
                bytes.len()
            );
            return Err(FatalError);
        }

        let version_end = version_payload_sizes::VERSION_SIZE;
        let version = i32::from_little_endian(&bytes[..version_end]).map_err(|e| {
            println!("Failed to construct version payload. Problem when reading version.");
            e
        })?;

        let services_end = version_end + version_payload_sizes::SERVICES_SIZE;
        let services = u64::from_little_endian(&bytes[version_end..services_end]).map_err(|e| {
            println!("Failed to construct version payload. Problem when reading services.");
            e
        })?;

        let timestamp_end = services_end + version_payload_sizes::TIMESTAMP_SIZE;
        let timestamp =
            i64::from_little_endian(&bytes[services_end..timestamp_end]).map_err(|e| {
                println!("Failed to construct version payload. Problem when reading timestamp.");
                e
            })?;

        let addr_recv_end = timestamp_end + version_payload_sizes::ADDR_RECV_SIZE;
        let addr_recv =
            NetworkAddress::from_bytes(&bytes[timestamp_end..addr_recv_end]).map_err(|e| {
                println!("Failed to construct version payload. Problem when reading addr_recv.");
                e
            })?;

        let addr_from_end = addr_recv_end + version_payload_sizes::ADDR_FROM_SIZE;
        let addr_from =
            NetworkAddress::from_bytes(&bytes[addr_recv_end..addr_from_end]).map_err(|e| {
                println!("Failed to construct version payload. Problem when reading addr_from.");
                e
            })?;

        let nonce_end = addr_from_end + version_payload_sizes::NONCE_SIZE;
        let nonce = u64::from_little_endian(&bytes[addr_from_end..nonce_end]).map_err(|e| {
            println!("Failed to construct version payload. Problem when reading nonce.");
            e
        })?;

        let user_agent_len = bytes[nonce_end];
        let user_agent_end = nonce_end + 1 + user_agent_len as usize;
        if bytes.len() < user_agent_end {
            println!("Failed to construct version payload. Problem when reading user_agent.");
            return Err(FatalError);
        }
        let user_agent = String::from_utf8(bytes[nonce_end + 1..user_agent_end].to_vec())
            .or(Err(FatalError))
            .map_err(|e| {
                println!("Failed to construct version payload. Problem when reading user_agent.");
                e
            })?;

        let last_block_end = user_agent_end + version_payload_sizes::LAST_BLOCK_RECEIVED_SIZE;
        if bytes.len() < last_block_end {
            println!("Failed to construct version payload. Problem when reading last_block.");
            return Err(FatalError);
        }
        let last_block =
            i32::from_little_endian(&bytes[user_agent_end..last_block_end]).map_err(|e| {
                println!("Failed to construct version payload. Problem when reading last_block.");
                e
            })?;

        Ok(Self {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            last_block,
        })
    }
}

#[cfg(test)]
mod version_tests {
    use crate::message_structures::network_address::{network_address_tests, NetworkAddress};
    use crate::message_structures::version::VersionPayload;
    use chrono::{TimeZone, Utc};

    fn get_test_version_payload() -> VersionPayload {
        VersionPayload {
            version: 31900,
            services: 1,
            timestamp: Utc
                .with_ymd_and_hms(2010, 12, 21, 2, 50, 14)
                .unwrap()
                .timestamp(), // Mon Dec 20 21:50:14 EST 2010
            addr_recv: NetworkAddress::new("10.0.0.1".to_string(), 8333, Some(1)),
            addr_from: NetworkAddress::new("10.0.0.1".to_string(), 8333, Some(1)),
            nonce: 0,
            user_agent: "".to_string(),
            last_block: 98645,
            relay: false,
        }
    }

    fn get_test_version_payload_bytes() -> Vec<u8> {
        let ver_bytes: [u8; 4] = [0x9C, 0x7C, 0x00, 0x00];
        let services_bytes: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let ts_bytes: [u8; 8] = [0xE6, 0x15, 0x10, 0x4D, 0x00, 0x00, 0x00, 0x00];
        let should_be_addr_recv = network_address_tests::get_test_net_addr_bytes();
        let should_be_addr_from = network_address_tests::get_test_net_addr_bytes();
        let nonce_bytes: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let ua_bytes: [u8; 1] = [0x00];
        let last_block_bytes: [u8; 4] = [0x55, 0x81, 0x01, 0x00];

        let mut bytes = vec![];
        bytes.extend(ver_bytes);
        bytes.extend(services_bytes);
        bytes.extend(ts_bytes);
        bytes.extend(should_be_addr_recv);
        bytes.extend(should_be_addr_from);
        bytes.extend(nonce_bytes);
        bytes.extend(ua_bytes);
        bytes.extend(last_block_bytes);

        bytes
    }

    #[test]
    fn version_payload_to_bytes_test() {
        let ver_payload = get_test_version_payload();
        let ver_payload_bytes = ver_payload.as_bytes();

        let should_be = get_test_version_payload_bytes();

        assert_eq!(ver_payload_bytes, Ok(should_be));
    }

    #[test]
    fn version_payload_from_bytes_test() {
        let bytes = get_test_version_payload_bytes();
        let ver_payload = VersionPayload::from_bytes(&bytes);

        let should_be = get_test_version_payload();

        assert_eq!(ver_payload, Ok(should_be));
    }
}
