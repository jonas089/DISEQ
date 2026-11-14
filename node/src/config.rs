//! Node configuration from environment variables.
use crate::dissemination::BatchConfig;
use diseq_consensus::timeouts::Timing;
use diseq_consensus::types::Timestamp;
use diseq_consensus::ConsensusConfig;
use std::env;
use std::str::FromStr;

/// Fixed default genesis time: genesis is part of the chain, so all nodes must agree on it.
pub const DEFAULT_GENESIS_TIMESTAMP: Timestamp = 1_725_000_000;

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub db_path: String,
    pub listen_addr: String,
    pub consensus: ConsensusConfig,
    pub batches: BatchConfig,
    pub tick_interval_ms: u64,
    pub sync_interval_ms: u64,
    /// Non-validator peers that receive proposals, votes and batches.
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
            db_path: var("PATH_TO_DB", "database".to_string()),
            listen_addr: var("API_HOST_WITH_PORT", "0.0.0.0:8080".to_string()),
            consensus: ConsensusConfig {
                timing: Timing {
                    propose_timeout_ms: var("PROPOSE_TIMEOUT_MS", 1_000),
                    prevote_timeout_ms: var("PREVOTE_TIMEOUT_MS", 1_000),
                    precommit_timeout_ms: var("PRECOMMIT_TIMEOUT_MS", 1_000),
                    timeout_delta_ms: var("TIMEOUT_DELTA_MS", 500),
                    rebroadcast_interval_ms: var("REBROADCAST_INTERVAL_MS", 2_000),
                    max_clock_drift: var("MAX_CLOCK_DRIFT", 2),
                },
                genesis_timestamp: var("GENESIS_TIMESTAMP", DEFAULT_GENESIS_TIMESTAMP),
                max_block_messages: var("MAX_BLOCK_MESSAGES", 1_000_000),
                max_block_batches: var("MAX_BLOCK_BATCHES", 1_000),
                expected_proposers: env::var("EXPECTED_PROPOSERS")
                    .ok()
                    .and_then(|v| v.parse().ok()),
                allow_empty_blocks: var("ALLOW_EMPTY_BLOCKS", false),
                max_pending_batches: var("MAX_PENDING_BATCHES", 10_000),
            },
            batches: BatchConfig {
                max_batch_messages: var("MAX_BATCH_MESSAGES", 4_096),
                batch_interval_ms: var("BATCH_INTERVAL_MS", 20),
                max_message_bytes: var("MAX_MESSAGE_BYTES", 64 * 1024),
                max_pending_messages: var("MAX_PENDING_MESSAGES", 200_000),
                max_inflight_batches: var("MAX_INFLIGHT_BATCHES", 256),
                retry_interval_ms: var("BATCH_RETRY_MS", 1_000),
            },
            tick_interval_ms: var("TICK_INTERVAL_MS", 10),
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
        config.consensus.validate();
        config
    }
}
