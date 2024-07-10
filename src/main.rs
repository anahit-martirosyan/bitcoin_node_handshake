mod bitcoin_node;
mod configs;
mod message_constructor;
mod message_structures;
pub mod sizes;
mod utils;

use crate::bitcoin_node::BitcoinNode;
use crate::configs::{LocalConfig, TargetNodeConfig};
use std::{env, fs};

#[tokio::main]
async fn main() {
    let local_config: LocalConfig = serde_json::from_str(
        &fs::read_to_string("./local_config.json").expect("Failed to read local configs."),
    )
    .expect("Failed to parse local config.");

    let target_node_config: TargetNodeConfig = serde_json::from_str(
        &fs::read_to_string("./target_node_config.json")
            .expect("Failed to read target node configs."),
    )
    .expect("Failed to parse target node config.");

    let bitcoin_node = BitcoinNode::new(local_config, target_node_config)
        .await
        .map_err(|e| {
            println!("Failed to start.");
            e
        });
    if bitcoin_node.is_err() {
        return;
    }

    let mut bitcoin_node = bitcoin_node.unwrap();
    let res = bitcoin_node.handshake().await;
    if res.is_err() {
        println!("Handshake failed.");
        return;
    } else {
        println!("Handshake succeeded.");
    }

    let n = env::var("READ_NEXT_N_MESSAGES")
        .unwrap_or_default()
        .parse::<u32>()
        .unwrap_or_default();
    let _ = bitcoin_node.read_messages_after_handshake(n).await;
}
