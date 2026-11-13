//! VRF based leader election (self-selection, as in Algorand / Ouroboros Praos).
//!
//! For height `h` and round `r` every validator evaluates its own VRF on
//! `input = H(randomness(parent) || h || r)`. Nobody else can compute that output, so the
//! winner is unknown until proposals are broadcast and an attacker cannot target the leader
//! ahead of time. Candidates attach the VRF proof to their proposal; validators vote for the
//! valid proposal with the best (lowest) priority.
//!
//! The randomness of a block is the hash of its proposer's VRF pre-output. Because the VRF
//! output is unique, a proposer cannot grind the next election's input by changing block
//! contents; its only option is to withhold its block.
//!
//! Priority uses an exponential race, `-ln(1 - u) / weight` with `u` uniform in [0, 1), so
//! validator `i` wins with probability exactly `weight_i / total_weight`. With equal weights
//! this is just "lowest VRF output wins". `libm` is used so floating point results are
//! identical on every platform.
use crate::types::{sha256, Block, Hash};
use std::cmp::Ordering;

pub fn block_randomness(block: &Block) -> Hash {
    match &block.vrf {
        Some(claim) => sha256(&[b"DISEQ_RANDOMNESS_V1", &claim.pre_output]),
        None => sha256(&[
            b"DISEQ_GENESIS_RANDOMNESS_V1",
            &block.timestamp.to_be_bytes(),
        ]),
    }
}

pub fn vrf_input(parent_randomness: &Hash, height: u32, round: u64) -> Vec<u8> {
    sha256(&[
        b"DISEQ_ELECTION_V1",
        parent_randomness,
        &height.to_be_bytes(),
        &round.to_be_bytes(),
    ])
    .to_vec()
}

/// Maps a VRF output to a uniform value in [0, 1) using its top 53 bits.
pub fn uniform(output: &Hash) -> f64 {
    let top = u64::from_be_bytes(output[..8].try_into().expect("8 bytes")) >> 11;
    top as f64 / (1u64 << 53) as f64
}

/// Lower is better.
pub fn priority(output: &Hash, weight: u64) -> f64 {
    -libm::log(1.0 - uniform(output)) / weight as f64
}

/// Optional sortition. With `expected_proposers = None` every validator is a candidate in
/// every round, which suits small permissioned sets. With `Some(tau)` a validator is a
/// candidate with probability `1 - (1 - tau / W)^weight`, so on average about `tau`
/// candidates propose per round, which keeps bandwidth bounded for large sets. Rounds with
/// no candidate are skipped.
pub fn is_eligible(
    output: &Hash,
    weight: u64,
    total_weight: u64,
    expected_proposers: Option<f64>,
) -> bool {
    match expected_proposers {
        None => true,
        Some(tau) => {
            let p_unit = (tau / total_weight as f64).min(1.0);
            let p = 1.0 - libm::pow(1.0 - p_unit, weight as f64);
            uniform(output) < p
        }
    }
}

/// Total order on candidates: lower priority wins, ties broken by block hash.
pub fn compare(a: (f64, &Hash), b: (f64, &Hash)) -> Ordering {
    a.0.total_cmp(&b.0).then_with(|| a.1.cmp(b.1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vrf::VrfKeypair;

    #[test]
    fn weighted_election_is_proportional() {
        // weights 1, 2, 3, 4: expected win rates 10%, 20%, 30%, 40%
        let keys: Vec<VrfKeypair> = (0..4u8).map(|i| VrfKeypair::from_seed(&[i; 32])).collect();
        let weights = [1u64, 2, 3, 4];
        let mut wins = [0u32; 4];
        let rounds = 10_000;
        for round in 0..rounds {
            let input = vrf_input(&[0; 32], 1, round);
            let priorities: Vec<f64> = (0..4)
                .map(|i| priority(&keys[i].prove(&input).0, weights[i]))
                .collect();
            let winner = (0..4)
                .min_by(|&a, &b| priorities[a].total_cmp(&priorities[b]))
                .unwrap();
            wins[winner] += 1;
        }
        for (i, w) in weights.iter().enumerate() {
            let expected = *w as f64 / 10.0;
            let observed = wins[i] as f64 / rounds as f64;
            assert!(
                (observed - expected).abs() < 0.015,
                "validator {i}: expected {expected}, observed {observed}"
            );
        }
    }

    #[test]
    fn sortition_selects_expected_number_of_candidates() {
        let keys: Vec<VrfKeypair> = (0..20u8).map(|i| VrfKeypair::from_seed(&[i; 32])).collect();
        let rounds = 1_000;
        let mut eligible = 0;
        for round in 0..rounds {
            let input = vrf_input(&[1; 32], 7, round);
            eligible += keys
                .iter()
                .filter(|k| is_eligible(&k.prove(&input).0, 1, 20, Some(5.0)))
                .count();
        }
        let avg = eligible as f64 / rounds as f64;
        assert!(
            (avg - 5.0).abs() < 0.3,
            "average candidates per round: {avg}"
        );
    }

    #[test]
    fn election_input_depends_on_height_and_round() {
        let r = [9; 32];
        assert_ne!(vrf_input(&r, 1, 0), vrf_input(&r, 1, 1));
        assert_ne!(vrf_input(&r, 1, 0), vrf_input(&r, 2, 0));
    }
}
