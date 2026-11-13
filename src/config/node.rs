use crate::consensus::logic::Timing;
use crate::types::Timestamp;
use std::env;
use std::str::FromStr;

/// Fixed default genesis time: genesis is part of the chain, so all nodes must agree on it.
pub const DEFAULT_GENESIS_TIMESTAMP: Timestamp = 1_725_000_000;

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub db_path: String,
    pub listen_addr: String,
    pub timing: Timing,
    pub genesis_timestamp: Timestamp,
    pub max_block_messages: usize,
    pub max_pool_size: usize,
    pub max_message_bytes: usize,
    /// `None`: every validator is a proposal candidate each round (default, small sets).
    /// `Some(tau)`: VRF sortition with ~tau candidates per round (large sets).
    pub expected_proposers: Option<f64>,
    /// Propose blocks even when the mempool is empty (heartbeat blocks).
    pub allow_empty_blocks: bool,
    pub tick_interval_ms: u64,
    pub sync_interval_ms: u64,
    /// Non-validator peers to gossip to in addition to the active validators.
    pub extra_peers: Vec<String>,
}

fn var<T: FromStr>(name: &str, default: T) -> T {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

impl NodeConfig {
    pub fn from_env() -> Self {
        let config = NodeConfig {
            db_path: var("PATH_TO_DB", "database.sqlite".to_string()),
            listen_addr: var("API_HOST_WITH_PORT", "0.0.0.0:8080".to_string()),
            timing: Timing {
                propose_timeout_ms: var("PROPOSE_TIMEOUT_MS", 3_000),
                prevote_timeout_ms: var("PREVOTE_TIMEOUT_MS", 1_000),
                precommit_timeout_ms: var("PRECOMMIT_TIMEOUT_MS", 1_000),
                timeout_delta_ms: var("TIMEOUT_DELTA_MS", 500),
                rebroadcast_interval_ms: var("REBROADCAST_INTERVAL_MS", 2_000),
                max_clock_drift: var("MAX_CLOCK_DRIFT", 2),
            },
            genesis_timestamp: var("GENESIS_TIMESTAMP", DEFAULT_GENESIS_TIMESTAMP),
            max_block_messages: var("MAX_BLOCK_MESSAGES", 10_000),
            max_pool_size: var("MAX_POOL_SIZE", 100_000),
            max_message_bytes: var("MAX_MESSAGE_BYTES", 64 * 1024),
            expected_proposers: env::var("EXPECTED_PROPOSERS")
                .ok()
                .and_then(|v| v.parse().ok()),
            allow_empty_blocks: var("ALLOW_EMPTY_BLOCKS", false),
            tick_interval_ms: var("TICK_INTERVAL_MS", 250),
            sync_interval_ms: var("SYNC_INTERVAL_MS", 2_000),
            extra_peers: env::var("EXTRA_PEERS")
                .map(|v| {
                    v.split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        };
        config.timing.validate();
        config
    }
}
