pub mod header_sizes {
    pub const MAGIC_BYTES_SIZE: usize = 4;
    pub const COMMAND_SIZE: usize = 12;
    pub const PAYLOAD_LENGTH_SIZE: usize = 4;
    pub const CHECKSUM_SIZE: usize = 4;
    pub const TOTAL_SIZE: usize = 24;
}

pub mod version_payload_sizes {
    pub const VERSION_SIZE: usize = 4;
    pub const SERVICES_SIZE: usize = 8;
    pub const TIMESTAMP_SIZE: usize = 8;
    pub const ADDR_RECV_SIZE: usize = 26;
    pub const ADDR_FROM_SIZE: usize = 26;
    pub const NONCE_SIZE: usize = 8;
    pub const LAST_BLOCK_RECEIVED_SIZE: usize = 4;

    pub const MIN_SIZE: usize = 84;
}

pub mod net_addr_sizes {
    pub const TIME_SIZE: usize = 4;
    pub const SERVICES_SIZE: usize = 8;
    pub const IPV6_SIZE: usize = 16;
    pub const PORT_SIZE: usize = 2;

    pub const TOTAL_SIZE: usize = 30;
}
