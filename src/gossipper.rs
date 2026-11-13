use anyhow::{Context, Result};
use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

/// HTTP gossip. Broadcasts are fire-and-forget; every receiver relays items that are new to it
/// (deduplicated by id), so a message reaches all peers even if some direct links fail.
#[derive(Debug, Clone)]
pub struct Gossipper {
    pub client: Client,
}

impl Default for Gossipper {
    fn default() -> Self {
        Self::new()
    }
}

impl Gossipper {
    pub fn new() -> Self {
        Gossipper {
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("http client"),
        }
    }

    pub fn broadcast<T: Serialize>(&self, peers: Vec<String>, path: &'static str, payload: &T) {
        let body = match serde_json::to_string(payload) {
            Ok(body) => body,
            Err(_) => return,
        };
        for peer in peers {
            let client = self.client.clone();
            let body = body.clone();
            tokio::spawn(async move {
                let _ = client
                    .post(format!("http://{peer}{path}"))
                    .header("Content-Type", "application/json")
                    .body(body)
                    .send()
                    .await;
            });
        }
    }

    pub async fn get_json<T: DeserializeOwned>(&self, peer: &str, path: &str) -> Result<T> {
        let response = self
            .client
            .get(format!("http://{peer}{path}"))
            .send()
            .await?
            .error_for_status()?;
        response.json().await.context("invalid response")
    }

    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        peer: &str,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let response = self
            .client
            .post(format!("http://{peer}{path}"))
            .json(body)
            .send()
            .await?
            .error_for_status()?;
        response.json().await.context("invalid response")
    }
}
