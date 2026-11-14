//! Vote bookkeeping for one height: storage, equivocation detection and tallies.
use crate::types::{GenericPublicKey, Hash, Vote, VoteKind};
use crate::validators::ValidatorSet;
use anyhow::{ensure, Result};
use std::collections::{HashMap, HashSet};

/// Whether an incoming item was new (and should be relayed) or already known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    New,
    Duplicate,
}

/// Votes of one height, by (kind, round).
///
/// Votes are unique per (validator, value). An equivocating validator can appear once per
/// value it signed: its vote then counts toward each of those values. That is safe (safety
/// only relies on honest validators) and needed for liveness, since different honest nodes
/// may have seen different votes from it.
#[derive(Default)]
pub struct VoteBook {
    votes: HashMap<(VoteKind, u64), Vec<Vote>>,
}

impl VoteBook {
    /// Records a vote whose signature was checked. A second vote of a validator for a
    /// different value (equivocation) is kept only if `known_value` (a block we have, or nil),
    /// which bounds memory: known blocks are limited to one per proposer and round.
    pub fn record(&mut self, vote: Vote, known_value: bool) -> Result<Received> {
        let votes = self.votes.entry((vote.kind, vote.round)).or_default();
        let mut equivocating = false;
        for existing in votes.iter().filter(|v| v.validator == vote.validator) {
            if existing.block_hash == vote.block_hash {
                return Ok(Received::Duplicate);
            }
            equivocating = true;
        }
        if equivocating {
            ensure!(
                known_value,
                "conflicting vote for unknown block in round {}",
                vote.round
            );
            crate::log_warn(format!(
                "validator {} equivocated ({:?}, round {})",
                hex::encode(&vote.validator[..4.min(vote.validator.len())]),
                vote.kind,
                vote.round
            ));
        }
        votes.push(vote);
        Ok(Received::New)
    }

    pub fn get(&self, kind: VoteKind, round: u64) -> &[Vote] {
        self.votes
            .get(&(kind, round))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&(VoteKind, u64), &Vec<Vote>)> {
        self.votes.iter()
    }

    /// Weight per voted value (block hash or nil), counting only active validators.
    pub fn tally(
        &self,
        set: &ValidatorSet,
        kind: VoteKind,
        round: u64,
    ) -> HashMap<Option<Hash>, u64> {
        tally(set, self.get(kind, round))
    }

    pub fn has_quorum(
        &self,
        set: &ValidatorSet,
        kind: VoteKind,
        round: u64,
        value: Option<Hash>,
    ) -> bool {
        self.tally(set, kind, round)
            .get(&value)
            .is_some_and(|w| set.is_quorum(*w))
    }

    /// Weight of distinct active validators that cast any vote of `kind` in `round`.
    pub fn voters_weight(&self, set: &ValidatorSet, kind: VoteKind, round: u64) -> u64 {
        weight_of(set, self.get(kind, round).iter().map(|v| &v.validator))
    }

    /// Weight of distinct validators with any vote in `round` (round skip evidence).
    pub fn round_weight(&self, set: &ValidatorSet, round: u64) -> u64 {
        let voters = [VoteKind::Prevote, VoteKind::Precommit]
            .into_iter()
            .flat_map(|k| self.get(k, round).iter().map(|v| &v.validator));
        weight_of(set, voters)
    }

    /// Rounds above `round` that have votes.
    pub fn later_rounds(&self, round: u64) -> HashSet<u64> {
        self.votes
            .keys()
            .map(|(_, r)| *r)
            .filter(|r| *r > round)
            .collect()
    }
}

pub fn tally(set: &ValidatorSet, votes: &[Vote]) -> HashMap<Option<Hash>, u64> {
    let mut weights = HashMap::new();
    for vote in votes {
        if let Some(v) = set.get(&vote.validator) {
            *weights.entry(vote.block_hash).or_insert(0) += v.weight;
        }
    }
    weights
}

fn weight_of<'a>(set: &ValidatorSet, ids: impl Iterator<Item = &'a GenericPublicKey>) -> u64 {
    let ids: HashSet<&GenericPublicKey> = ids.collect();
    ids.into_iter()
        .filter_map(|id| set.get(id))
        .map(|v| v.weight)
        .sum()
}
