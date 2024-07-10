use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct TargetNodeConfig {
    pub ipv4: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize)]
pub struct LocalConfig {
    pub version: i32,
    #[serde(default = "default_services")]
    pub services: u64,
    #[serde(default = "default_ip")]
    pub ipv4: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_services() -> u64 {
    0
}

fn default_ip() -> String {
    "".to_string()
}

fn default_port() -> u16 {
    0
}
