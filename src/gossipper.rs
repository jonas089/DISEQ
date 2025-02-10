use crate::types::ConsensusCommitment;
use crate::{consensus::logic::current_round, types::Block};
use colored::Colorize;
use reqwest::{Client, Response};
use std::{env, time::Duration};
use tokio::time::sleep;
pub type Peer = &'static str;
pub struct Gossipper {
    pub peers: Vec<Peer>,
    pub client: Client,
}
pub async fn send_proposal(client: Client, peer: Peer, json_block: String) -> Option<Response> {
    let response: Option<Response> = match client
        .post(format!("http://{}{}", &peer, "/propose"))
        .header("Content-Type", "application/json")
        .body(json_block)
        //.timeout(Duration::from_secs(30))
        .send()
        .await
    {
        Ok(r) => Some(r),
        Err(_) => None,
    };
    response
}

impl Gossipper {
    pub async fn gossip_pending_block(&self, block: Block, last_block_unix_timestamp: u32) {
        for peer in self.peers.clone() {
            let client_clone = self.client.clone();
            let peer_clone = peer;
            let json_block: String = serde_json::to_string(&block).unwrap();
            let this_node = env::var("API_HOST_WITH_PORT").unwrap_or("0.0.0.0:8080".to_string());
            if docker_skip_self(&this_node, peer) {
                continue;
            };
            tokio::spawn(async move {
                let start_round = current_round(last_block_unix_timestamp);
                let round = current_round(last_block_unix_timestamp);
                if start_round < round {
                    println!("[Warning] Gossipping old Block");
                }
                let response =
                    match send_proposal(client_clone.clone(), peer_clone, json_block.clone()).await
                    {
                        Some(r) => r
                            .text()
                            .await
                            .unwrap_or("[Err] Peer unresponsive".to_string()),
                        None => "[Err] Failed to send request".to_string(),
                    };
                if response == "[Ok] Block was processed" {
                    println!(
                        "{}",
                        format_args!(
                            "{} Block was successfully sent to peer: {}",
                            "[Info]".green(),
                            &peer_clone
                        )
                    );
                } else {
                    println!(
                        "{}",
                        format_args!(
                            "{} Failed to gossip to peer: {}, response: {}",
                            "[Error]".red(),
                            &peer_clone,
                            response
                        )
                    );
                    sleep(Duration::from_secs(1)).await;
                }
            });
        }
    }

    pub async fn gossip_consensus_commitment(&self, commitment: ConsensusCommitment) {
        let json_commitment: String = serde_json::to_string(&commitment).unwrap();
        for peer in self.peers.clone() {
            let client_clone = self.client.clone();
            let json_commitment_clone: String = json_commitment.clone();
            let this_node = env::var("API_HOST_WITH_PORT").unwrap_or("0.0.0.0:8080".to_string());
            if docker_skip_self(&this_node, peer) {
                continue;
            };
            tokio::spawn(async move {
                match client_clone
                    .post(format!("http://{}{}", &peer, "/commit"))
                    .header("Content-Type", "application/json")
                    .body(json_commitment_clone)
                    //.timeout(Duration::from_secs(20))
                    .send()
                    .await
                {
                    Ok(_) => {
                        println!(
                            "{}",
                            format_args!(
                                "{} Successfully sent consensus commitment to peer: {}",
                                "[Info]".yellow(),
                                &peer,
                            )
                        );
                    }
                    Err(e) => println!(
                        "{}",
                        format_args!(
                            "{} Failed to send Consensus Commitment to peer: {}, {}, reason: {}",
                            "[Warning]".yellow(),
                            &peer,
                            "Proceeding with other peers",
                            e
                        )
                    ),
                }
            });
        }
    }
}
pub fn docker_skip_self(this_node: &str, peer: &str) -> bool {
    if this_node == "0.0.0.0:8080" && peer == "rust-node-1:8080" {
        return true;
    } else if this_node == "0.0.0.0:8081" && peer == "rust-node-2:8081" {
        return true;
    } else if this_node == "0.0.0.0:8082" && peer == "rust-node-3:8082" {
        return true;
    } else if this_node == "0.0.0.0:8083" && peer == "rust-node-4:8083" {
        return true;
    }
    false
}
