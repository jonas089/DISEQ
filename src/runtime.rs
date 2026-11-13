//! Wires a [`Node`] to the network: HTTP API, consensus ticker, block sync and mempool
//! anti-entropy.
use crate::api::{broadcast_outgoing, router, AppState, POOL_FETCH_LIMIT};
use crate::config::node::NodeConfig;
use crate::consensus::validators::ValidatorSetPolicy;
use crate::get_current_time_ms;
use crate::gossipper::Gossipper;
use crate::node::{log_info, log_warn, LocalValidator, Node};
use crate::types::{Block, Hash};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

pub struct NodeHandle {
    pub node: Arc<Mutex<Node>>,
    pub tasks: Vec<JoinHandle<()>>,
}

impl NodeHandle {
    /// Runs until one of the node's tasks exits, then stops the others.
    pub async fn wait(mut self) {
        let tasks = std::mem::take(&mut self.tasks);
        let aborts: Vec<_> = tasks.iter().map(|t| t.abort_handle()).collect();
        let mut set = tokio::task::JoinSet::new();
        for task in tasks {
            set.spawn(task);
        }
        let _ = set.join_next().await;
        // aborting the JoinSet only drops the inner handles, so abort the tasks themselves
        for abort in aborts {
            abort.abort();
        }
    }
}

impl Drop for NodeHandle {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

pub async fn spawn_node(
    config: NodeConfig,
    policy: Box<dyn ValidatorSetPolicy>,
    identity: Option<LocalValidator>,
) -> Result<NodeHandle> {
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    let tick = Duration::from_millis(config.tick_interval_ms);
    let sync_interval = Duration::from_millis(config.sync_interval_ms);
    let node = Arc::new(Mutex::new(Node::new(config, policy, identity)?));
    let state = AppState {
        node: node.clone(),
        gossip: Gossipper::new(),
    };

    let api = tokio::spawn({
        let app = router(state.clone());
        async move {
            if let Err(e) = axum::serve(listener, app).await {
                log_warn(format!("API server stopped: {e}"));
            }
        }
    });

    let consensus = tokio::spawn({
        let state = state.clone();
        async move {
            loop {
                let result = {
                    let mut node = state.node.lock().await;
                    node.on_tick(get_current_time_ms())
                        .and_then(|out| Ok((out, node.peers()?)))
                };
                match result {
                    Ok((outgoing, peers)) => broadcast_outgoing(&state.gossip, &peers, outgoing),
                    Err(e) => log_warn(format!("consensus tick failed: {e:#}")),
                }
                tokio::time::sleep(tick).await;
            }
        }
    });

    let sync = tokio::spawn({
        let state = state.clone();
        async move {
            loop {
                tokio::time::sleep(sync_interval).await;
                if let Err(e) = sync_once(&state).await {
                    log_warn(format!("sync failed: {e:#}"));
                }
            }
        }
    });

    Ok(NodeHandle {
        node,
        tasks: vec![api, consensus, sync],
    })
}

/// Pulls missing blocks and mempool messages from every peer.
async fn sync_once(state: &AppState) -> Result<()> {
    let peers = state.node.lock().await.peers()?;
    for peer in peers {
        // blocks: catch up one certified block at a time
        if let Ok(peer_height) = state.gossip.get_json::<u32>(&peer, "/get/height").await {
            loop {
                let next = state.node.lock().await.store.latest_height()? + 1;
                if next > peer_height {
                    break;
                }
                let block: Block = match state
                    .gossip
                    .get_json(&peer, &format!("/get/block/{next}"))
                    .await
                {
                    Ok(block) => block,
                    Err(_) => break,
                };
                let mut node = state.node.lock().await;
                // the block may have been committed via gossip in the meantime
                if node.store.latest_height()? + 1 != next {
                    continue;
                }
                match node.on_certified_block(block) {
                    Ok(()) => log_info(format!("Synchronized block {next} from {peer}")),
                    Err(e) => {
                        log_warn(format!("rejected block {next} from {peer}: {e:#}"));
                        break;
                    }
                }
            }
        }

        // mempool anti-entropy: fetch messages the peer has and we lack
        let Ok(ids) = state
            .gossip
            .get_json::<Vec<Hash>>(&peer, "/get/pool/ids")
            .await
        else {
            continue;
        };
        let missing: Vec<Hash> = {
            let node = state.node.lock().await;
            let mut missing = Vec::new();
            for id in ids {
                if !node.store.pool_contains(&id)? && !node.store.is_committed(&id)? {
                    missing.push(id);
                }
            }
            missing
        };
        for chunk in missing.chunks(POOL_FETCH_LIMIT) {
            let messages: Vec<crate::types::Message> = match state
                .gossip
                .post_json(&peer, "/get/pool/messages", &chunk)
                .await
            {
                Ok(m) => m,
                Err(_) => break,
            };
            let mut node = state.node.lock().await;
            for message in messages {
                // ids are recomputed locally, so a peer cannot inject under a wrong id
                let _ = node.submit_message(&message);
            }
        }
    }
    Ok(())
}
