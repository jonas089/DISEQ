//! Round timeouts (Tendermint style). Rounds advance on local timeouts and on evidence that
//! more than 1/3 of the weight is already in a later round, so validators do not need
//! synchronized clocks. Timeouts grow linearly with the round so that, once the network is
//! synchronous, some round eventually lasts long enough to commit.

#[derive(Clone, Debug)]
pub struct Timing {
    /// How long to collect proposals before prevoting.
    pub propose_timeout_ms: u64,
    /// How long to wait after seeing 2/3+ prevotes (but no 2/3+ for one value) before
    /// precommitting nil.
    pub prevote_timeout_ms: u64,
    /// How long to wait after seeing 2/3+ precommits (without a commit) before moving on.
    pub precommit_timeout_ms: u64,
    /// Added to every timeout per round.
    pub timeout_delta_ms: u64,
    /// Validators re-send their own votes (and the proposals they voted for) at this
    /// interval until the height commits. Gossip is best-effort, so without retransmission
    /// a few lost messages could stall a round forever.
    pub rebroadcast_interval_ms: u64,
    /// Tolerated clock skew (seconds) for block timestamps.
    pub max_clock_drift: u32,
}

/// Rounds beyond this the timeouts stop growing.
const MAX_TIMEOUT_ROUND: u64 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
}

impl Timing {
    fn scaled(&self, base: u64, round: u64) -> u64 {
        base + self.timeout_delta_ms * round.min(MAX_TIMEOUT_ROUND)
    }
    pub fn propose(&self, round: u64) -> u64 {
        self.scaled(self.propose_timeout_ms, round)
    }
    pub fn prevote(&self, round: u64) -> u64 {
        self.scaled(self.prevote_timeout_ms, round)
    }
    pub fn precommit(&self, round: u64) -> u64 {
        self.scaled(self.precommit_timeout_ms, round)
    }
    pub fn validate(&self) {
        assert!(
            self.propose_timeout_ms > 0,
            "propose timeout must be positive"
        );
        assert!(
            self.rebroadcast_interval_ms > 0,
            "rebroadcast interval must be positive"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_grow_with_round_and_are_capped() {
        let t = Timing {
            propose_timeout_ms: 1000,
            prevote_timeout_ms: 500,
            precommit_timeout_ms: 500,
            timeout_delta_ms: 100,
            rebroadcast_interval_ms: 1000,
            max_clock_drift: 1,
        };
        assert_eq!(t.propose(0), 1000);
        assert_eq!(t.propose(3), 1300);
        assert_eq!(t.prevote(1_000_000), 500 + 100 * MAX_TIMEOUT_ROUND);
    }
}
