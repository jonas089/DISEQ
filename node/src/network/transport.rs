//! Peer-to-peer transport: bincode over HTTP with per-peer batching.
//!
//! Every peer gets two sender tasks, one for consensus traffic and one for data (batches),
//! each fed by a bounded queue. A sender has at most one request in flight;
//! whatever queues up meanwhile goes out as the next batch, so batches grow with load and a
//! lone item is sent immediately. Items are encoded once and the same bytes are reused for
//! every peer ([`wire::encode_batch`]).
//!
//! Delivery is best effort. A full queue (slow or dead peer) drops items: votes and proposals
//! are retransmitted by consensus, batches and certificates by their author until committed,
//! and a missing batch is fetched on demand.
use super::wire::{self, BINCODE};
use anyhow::{Context, Result};
use bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

pub const CONSENSUS_PATH: &str = "/p2p/consensus";
pub const DATA_PATH: &str = "/p2p/data";

const CONSENSUS_QUEUE: usize = 16_384;
const DATA_QUEUE: usize = 1_024;
const MAX_CONSENSUS_BATCH: usize = 1_024;
/// Batches are up to a few hundred KB each; keep requests well below the wire limit.
const MAX_DATA_BATCH: usize = 16;

struct Peer {
    consensus: mpsc::Sender<Bytes>,
    data: mpsc::Sender<Bytes>,
}

#[derive(Clone)]
pub struct Net {
    client: reqwest::Client,
    runtime: Handle,
    peers: Arc<Mutex<HashMap<String, Peer>>>,
}

impl Net {
    /// `runtime` runs the sender tasks; sending itself works from any thread.
    pub fn new(runtime: Handle) -> Self {
        Net {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .tcp_nodelay(true)
                .pool_max_idle_per_host(8)
                .build()
                .expect("http client"),
            runtime,
            peers: Arc::default(),
        }
    }

    fn with_peer(&self, addr: &str, f: impl FnOnce(&Peer)) {
        let mut peers = self.peers.lock().expect("peer map poisoned");
        let peer = peers.entry(addr.to_string()).or_insert_with(|| {
            let (consensus, consensus_rx) = mpsc::channel(CONSENSUS_QUEUE);
            let (data, data_rx) = mpsc::channel(DATA_QUEUE);
            let client = self.client.clone();
            self.runtime.spawn(sender(
                client.clone(),
                addr.to_string(),
                CONSENSUS_PATH,
                consensus_rx,
                MAX_CONSENSUS_BATCH,
            ));
            self.runtime.spawn(sender(
                client,
                addr.to_string(),
                DATA_PATH,
                data_rx,
                MAX_DATA_BATCH,
            ));
            Peer { consensus, data }
        });
        f(peer)
    }

    /// Queues an encoded [`super::PeerMsg`] for every peer in `peers`.
    pub fn send_consensus(&self, peers: &[String], item: Bytes) {
        for addr in peers {
            self.with_peer(addr, |p| {
                let _ = p.consensus.try_send(item.clone());
            });
        }
    }

    /// Queues an encoded [`super::DataMsg`] for every peer in `peers`.
    pub fn send_data(&self, peers: &[String], item: Bytes) {
        for addr in peers {
            self.with_peer(addr, |p| {
                let _ = p.data.try_send(item.clone());
            });
        }
    }

    pub async fn get<T: DeserializeOwned>(&self, peer: &str, path: &str) -> Result<T> {
        let body = self
            .client
            .get(format!("http://{peer}{path}"))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        wire::decode(&body).context("invalid response")
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        peer: &str,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let body = self
            .client
            .post(format!("http://{peer}{path}"))
            .header("Content-Type", BINCODE)
            .body(wire::encode(body)?)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        wire::decode(&body).context("invalid response")
    }
}

async fn sender(
    client: reqwest::Client,
    addr: String,
    path: &'static str,
    mut rx: mpsc::Receiver<Bytes>,
    max_batch: usize,
) {
    let url = format!("http://{addr}{path}");
    let mut batch = Vec::with_capacity(max_batch);
    while rx.recv_many(&mut batch, max_batch).await > 0 {
        if let Ok(body) = wire::encode_batch(&batch) {
            let _ = client
                .post(&url)
                .header("Content-Type", BINCODE)
                .body(body)
                .send()
                .await;
        }
        batch.clear();
    }
}
