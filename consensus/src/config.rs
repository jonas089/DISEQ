use crate::timeouts::Timing;
use crate::types::Timestamp;

/// Protocol parameters. Every validator of a network must use the same values for
/// `genesis_timestamp`, `max_block_messages`, `max_block_batches` and `expected_proposers`.
#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    pub timing: Timing,
    pub genesis_timestamp: Timestamp,
    /// Upper bound on the summed message count of a block's batches.
    pub max_block_messages: u64,
    pub max_block_batches: usize,
    /// `None`: every validator is a proposal candidate each round (default, small sets).
    /// `Some(tau)`: VRF sortition with ~tau candidates per round (large sets).
    pub expected_proposers: Option<f64>,
    /// Propose blocks without batches (heartbeat blocks).
    pub allow_empty_blocks: bool,
    /// Certified batches waiting for a block; further certificates are refused.
    pub max_pending_batches: usize,
}

impl ConsensusConfig {
    pub fn validate(&self) {
        self.timing.validate();
        assert!(self.max_block_batches > 0, "blocks must hold batches");
    }
}
