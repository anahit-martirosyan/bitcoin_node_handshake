const IP_PREFIX_BYTES_SIZE: usize = 12;
static IPV4_BYTES_SIZE: usize = 4;
static IP_PREFIX: [u8; IP_PREFIX_BYTES_SIZE] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
];

use crate::sizes::net_addr_sizes;
use crate::utils::HandshakeError::{FatalError, NonFatalError};
use crate::utils::{FromBigEndian, FromLittleEndian, HandshakeError, ToBigEndian, ToLittleEndian};
use std::cmp::PartialEq;

#[derive(Default, PartialEq, Eq, Debug)]
pub struct NetworkAddress {
    //time: u32, // ignoring 'time' for now as it's not present in version message
    services: u64,
    ip: String,
    port: u16,
}

impl NetworkAddress {
    pub fn new(ip: String, port: u16, services: Option<u64>) -> Self {
        Self {
            services: services.unwrap_or_default(),
            ip,
            port,
        }
    }

    fn get_ip_bytes(&self) -> Result<Vec<u8>, HandshakeError> {
        let ip_bytes = self
            .ip
            .split('.')
            .map(|n| n.parse::<u8>().ok())
            .collect::<Vec<Option<u8>>>();

        if ip_bytes.iter().any(|n| n.is_none()) {
            // Failed to parse some part of the ip
            return Err(NonFatalError);
        }

        let mut ip_bytes = ip_bytes
            .into_iter()
            .map(|n| n.unwrap())
            .collect::<Vec<u8>>();

        let mut res = IP_PREFIX.to_vec();
        res.append(&mut ip_bytes);

        Ok(res)
    }

    fn ip_from_bytes(bytes: &[u8]) -> Result<String, HandshakeError> {
        if bytes[..IP_PREFIX_BYTES_SIZE] != IP_PREFIX {
            // println!("Failed to construct ip. Wrong ip prefix. {}", bytes_to_str(bytes.to_vec()));
            return Err(NonFatalError);
        }

        if bytes.len() - IP_PREFIX_BYTES_SIZE < IPV4_BYTES_SIZE {
            return Err(NonFatalError);
        }
        let ip = bytes[IP_PREFIX_BYTES_SIZE..]
            .iter()
            .map(|b| format!("{}", b))
            .collect::<Vec<String>>()
            .join(".");

        Ok(ip)
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, HandshakeError> {
        // currently skipping 'time' as it's not present in version message
        let mut res = vec![];
        res.append(&mut self.services.to_little_endian()?);
        let ip_bytes = self.get_ip_bytes();
        if let Err(e) = &ip_bytes {
            if *e == FatalError {
                return Err(FatalError);
            }
        }

        res.append(&mut ip_bytes.unwrap_or(vec![0; net_addr_sizes::IPV6_SIZE]));
        res.append(&mut self.port.to_big_endian()?);

        Ok(res)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HandshakeError> {
        // currently skipping 'time' as it's not present in version message
        let expected_bytes_len = net_addr_sizes::TOTAL_SIZE - net_addr_sizes::TIME_SIZE;

        if bytes.len() < expected_bytes_len {
            println!(
                "Failed to construct network address. Waiting for {} bytes, got {} bytes",
                expected_bytes_len,
                bytes.len()
            );
            return Err(FatalError);
        }

        let services_end = net_addr_sizes::SERVICES_SIZE;
        let services = u64::from_little_endian(&bytes[..services_end]).map_err(|e| {
            println!("Failed to construct network address. Problem when reading services.");
            e
        })?;

        let ip_end = services_end + net_addr_sizes::IPV6_SIZE;
        let ip = Self::ip_from_bytes(&bytes[services_end..ip_end]).unwrap_or_default();

        let port_end = ip_end + net_addr_sizes::PORT_SIZE;

        let port = u16::from_big_endian(&bytes[ip_end..port_end]).map_err(|e| {
            println!("Failed to construct network address. Problem when reading port.");
            e
        })?;

        Ok(Self { services, ip, port })
    }
}

#[cfg(test)]
pub mod network_address_tests {
    use crate::message_structures::network_address::{NetworkAddress, IP_PREFIX};

    fn get_test_net_addr() -> NetworkAddress {
        NetworkAddress {
            services: 1,
            ip: "10.0.0.1".to_string(),
            port: 8333,
        }
    }

    pub fn get_test_net_addr_bytes() -> Vec<u8> {
        let services_bytes: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut ip_bytes: [u8; 16] = [0; 16];
        ip_bytes[..12].copy_from_slice(&IP_PREFIX);
        ip_bytes[12..].copy_from_slice(&[0x0A, 0x00, 0x00, 0x01]);
        let port_bytes: [u8; 2] = [0x20, 0x8D];

        let mut bytes = vec![];
        bytes.extend(services_bytes);
        bytes.extend(ip_bytes);
        bytes.extend(port_bytes);

        bytes
    }

    #[test]
    fn network_addr_to_bytes_test() {
        let network_addr = get_test_net_addr();
        let network_addr_bytes = network_addr.as_bytes();

        let should_be = get_test_net_addr_bytes();

        assert_eq!(network_addr_bytes, Ok(should_be));
    }

    #[test]
    fn network_addr_from_bytes_test() {
        let bytes = get_test_net_addr_bytes();
        let net_addr = NetworkAddress::from_bytes(&bytes);

        let should_be = get_test_net_addr();

        assert_eq!(net_addr, Ok(should_be));
    }
}
