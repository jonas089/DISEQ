#[cfg(test)]
mod tests {
    use patricia_trie::{
        merkle::{verify_merkle_proof, MerkleProof},
        store::types::{Hashable, Leaf, Root},
    };
    use pord_sequencer::types::Transaction;
    use prover::generate_random_number;
    use reqwest::{Client, Response};
    use std::{env, time::Duration};
    use tokio::time::sleep;
    use {
        pord_sequencer::config::network::PEERS, pord_sequencer::gossipper::Gossipper,
        pord_sequencer::types::ConsensusCommitment,
    };

    async fn submit_transaction(client: Client, transaction_json: String) -> Response {
        client
            .post("http://127.0.0.1:8080/schedule")
            .header("Content-Type", "application/json")
            .body(transaction_json.clone())
            .send()
            .await
            .unwrap()
    }

    async fn request_merkle_proof(client: Client, transaction_key_json: String) -> Response {
        client
            .post("http://127.0.0.1:8080/merkle_proof")
            .header("Content-Type", "application/json")
            .body(transaction_key_json)
            .send()
            .await
            .unwrap()
    }

    async fn get_state_root_hash(client: Client) -> Response {
        client
            .get("http://127.0.0.1:8080/get/state_root_hash")
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn await_transaction_and_verify_merkle_proof() {
        let client = Client::new();
        let transaction: Transaction = Transaction {
            data: vec![1, 2, 3, 4, 5],
            timestamp: 0,
        };
        let transaction_json: String = serde_json::to_string(&transaction).unwrap();
        let transaction_response = submit_transaction(client.clone(), transaction_json).await;
        assert_eq!(
            transaction_response.text().await.unwrap(),
            "[Ok] Transaction is being sequenced: Transaction { data: [1, 2, 3, 4, 5], timestamp: 0 }"
        );
        let mut node_trie_root: Option<Root> = None;
        // wait a maximum of ~ 5 blocks
        for _180_seconds in 0..5 {
            let trie_root_json = get_state_root_hash(client.clone())
                .await
                .text()
                .await
                .unwrap();
            let trie_root: Root = serde_json::from_str(&trie_root_json).unwrap();
            match trie_root.hash.clone() {
                Some(_) => {
                    node_trie_root = Some(trie_root.clone());
                    break;
                }
                None => {}
            };
            sleep(Duration::from_secs(5)).await;
        }
        let mut leaf = Leaf::new(Vec::new(), Some(transaction.data.clone()));
        leaf.hash();
        leaf.key = leaf
            .hash
            .clone()
            .unwrap()
            .iter()
            .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1))
            .collect();
        leaf.hash();
        let transaction_key_json = serde_json::to_string(&leaf.key).unwrap();
        let merkle_proof_response =
            request_merkle_proof(client.clone(), transaction_key_json).await;
        let merkle_proof_json = merkle_proof_response.text().await.unwrap();
        let merkle_proof: MerkleProof = serde_json::from_str(&merkle_proof_json).unwrap();
        verify_merkle_proof(
            merkle_proof.nodes,
            node_trie_root
                .expect("[Error] No Trie Root present!")
                .hash
                .unwrap(),
        );
    }

    #[tokio::test]
    async fn test_schedule_transaction() {
        let client = Client::new();
        let transaction: Transaction = Transaction {
            data: vec![1, 2, 3, 4, 5],
            timestamp: 0,
        };
        let transaction_json: String = serde_json::to_string(&transaction).unwrap();
        // note that currently a transaction may only be submitted to one node
        // mishandling this can cause the network to crash
        let transaction_response = submit_transaction(client, transaction_json).await;
        assert_eq!(
            transaction_response.text().await.unwrap(),
            "[Ok] Transaction is being sequenced: Transaction { data: [1, 2, 3, 4, 5], timestamp: 0 }"
        );
    }

    #[tokio::test]
    async fn test_commit() {
        let receipt = generate_random_number(vec![0; 32], vec![0; 32]);
        let consensus_commitment: ConsensusCommitment = ConsensusCommitment {
            validator: vec![0; 32],
            receipt,
        };
        let gossipper = Gossipper {
            peers: PEERS.to_vec(),
            client: Client::new(),
        };
        env::set_var("API_HOST_WITH_PORT", "127.0.0.1:8081");
        gossipper
            .gossip_consensus_commitment(consensus_commitment)
            .await;
    }
}
