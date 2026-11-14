//! Tests against a running docker network (`docker compose up`); ignored by default.
#[cfg(test)]
mod tests {
    use ciphercurve_trie::{verify, Proof, ProofStep};
    use diseq_consensus::types::Message;
    use reqwest::Client;
    use serde::Deserialize;
    use std::time::Duration;

    const NODE: &str = "http://127.0.0.1:8080";

    #[derive(Deserialize)]
    struct MessageStatus {
        sequenced_at: Option<u32>,
    }
    #[derive(Deserialize)]
    struct StepView {
        prefix_len: u8,
        bitmap: u16,
        siblings: Vec<String>,
    }
    #[derive(Deserialize)]
    struct ProofView {
        root: String,
        steps: Vec<StepView>,
    }

    fn hash(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str).unwrap().try_into().unwrap()
    }

    #[tokio::test]
    #[ignore = "requires the docker network"]
    async fn schedule_and_verify_merkle_proof() {
        let client = Client::new();
        let message = Message {
            data: format!("api test {:?}", std::time::SystemTime::now()).into_bytes(),
            timestamp: 0,
        };
        let reply = client
            .post(format!("{NODE}/schedule"))
            .json(&message)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(reply.starts_with("[Ok]"), "{reply}");
        let id = hex::encode(message.id());

        // wait until the message is final
        for _ in 0..120 {
            let status: MessageStatus = client
                .get(format!("{NODE}/get/message/{id}"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if status.sequenced_at.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        // the trie may trail the sequence by a moment
        let mut proof = None;
        for _ in 0..40 {
            let response = client
                .get(format!("{NODE}/merkle_proof/{id}"))
                .send()
                .await
                .unwrap();
            if response.status().is_success() {
                proof = Some(response.json::<ProofView>().await.unwrap());
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let view = proof.expect("message never appeared in the trie");
        let proof = Proof {
            steps: view
                .steps
                .iter()
                .map(|s| ProofStep {
                    prefix_len: s.prefix_len,
                    bitmap: s.bitmap,
                    siblings: s.siblings.iter().map(|h| hash(h)).collect(),
                })
                .collect(),
        };
        let id = message.id();
        assert!(verify(&hash(&view.root), &id, &id, &proof));
    }
}
