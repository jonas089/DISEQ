//! Validator sets and the pluggable policy that decides who validates at which height.
//!
//! The default is [`FixedValidatorSet`]: a static, permissioned set. Any other rule set
//! (proof of stake, governance, reputation, an L1 staking contract, ...) can be plugged in by
//! implementing [`ValidatorSetPolicy`]. [`EpochStakePolicy`] is a reference PoS-style policy.
use crate::types::{Block, GenericPublicKey};
use k256::ecdsa::VerifyingKey;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    /// ECDSA key used for proposals and votes.
    pub id: VerifyingKey,
    /// Schnorrkel VRF public key used for leader election.
    pub vrf_key: Vec<u8>,
    /// Voting and election weight (1 in a fixed set, stake in PoS).
    pub weight: u64,
    /// Network address used for gossip, e.g. `rust-node-1:8080`.
    pub address: String,
}
impl Validator {
    pub fn id_bytes(&self) -> GenericPublicKey {
        self.id.to_sec1_bytes().to_vec()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
}
impl ValidatorSet {
    pub fn new(validators: Vec<Validator>) -> Self {
        assert!(!validators.is_empty(), "validator set must not be empty");
        assert!(
            validators.iter().all(|v| v.weight > 0),
            "validator weights must be positive"
        );
        let mut ids: Vec<_> = validators.iter().map(|v| v.id_bytes()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), validators.len(), "duplicate validator");
        ValidatorSet { validators }
    }
    pub fn get(&self, id: &[u8]) -> Option<&Validator> {
        self.validators.iter().find(|v| v.id_bytes() == id)
    }
    pub fn iter(&self) -> impl Iterator<Item = &Validator> {
        self.validators.iter()
    }
    pub fn len(&self) -> usize {
        self.validators.len()
    }
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }
    pub fn total_weight(&self) -> u64 {
        self.validators.iter().map(|v| v.weight).sum()
    }
    /// BFT quorum: strictly more than 2/3 of the total weight. Tolerates f < n/3 faulty weight.
    pub fn is_quorum(&self, weight: u64) -> bool {
        (weight as u128) * 3 > (self.total_weight() as u128) * 2
    }
}

/// Decides which validators are active for a given height.
///
/// Implementations must be deterministic functions of the committed chain: every honest node
/// that has committed blocks `0..height` must return the same set for `height`. A rule that
/// reacts to chain contents (staking messages, slashing evidence, ...) updates its state in
/// [`ValidatorSetPolicy::on_block_committed`]. Changes should take effect with a delay
/// (e.g. at the next epoch) so that nodes slightly behind still agree on the current set.
pub trait ValidatorSetPolicy: Send + Sync + 'static {
    fn validator_set(&self, height: u32) -> ValidatorSet;
    /// Called exactly once per committed block, in height order, including on startup when
    /// the node replays its stored chain.
    fn on_block_committed(&mut self, _block: &Block) {}
}

/// Default policy: the same permissioned set for every height.
pub struct FixedValidatorSet(pub ValidatorSet);
impl ValidatorSetPolicy for FixedValidatorSet {
    fn validator_set(&self, _height: u32) -> ValidatorSet {
        self.0.clone()
    }
}

/// A registered validator candidate with its stake.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub validator: Validator,
    pub stake: u64,
}

/// Reference proof-of-stake policy with epoch based rotation.
///
/// Every `epoch_length` blocks the top `max_validators` candidates by stake become the active
/// set, weighted by stake. The set for epoch `e` is computed from the stake table at the end
/// of epoch `e - 1`, so a node always knows the set for the height it is working on.
/// How stake changes is left to `apply_block`: block rewards, deposits bridged from an L1
/// contract, slashing, etc. Policies see ordered blocks (batch certificates), not message
/// payloads: payloads are resolved after ordering. A payload-driven rule (staking messages)
/// must be fed from the sequenced output and take effect with at least one epoch of delay.
pub struct EpochStakePolicy<F> {
    pub epoch_length: u32,
    pub max_validators: usize,
    candidates: BTreeMap<GenericPublicKey, Candidate>,
    /// Active set per epoch.
    epochs: BTreeMap<u32, ValidatorSet>,
    apply_block: F,
}

impl<F> EpochStakePolicy<F>
where
    F: FnMut(&Block, &mut BTreeMap<GenericPublicKey, Candidate>) + Send + Sync + 'static,
{
    pub fn new(
        epoch_length: u32,
        max_validators: usize,
        genesis_candidates: Vec<Candidate>,
        apply_block: F,
    ) -> Self {
        assert!(epoch_length > 0);
        let candidates = genesis_candidates
            .into_iter()
            .map(|c| (c.validator.id_bytes(), c))
            .collect();
        let mut policy = EpochStakePolicy {
            epoch_length,
            max_validators,
            candidates,
            epochs: BTreeMap::new(),
            apply_block,
        };
        let genesis_set = policy.select();
        policy.epochs.insert(0, genesis_set);
        policy
    }
    fn epoch_of(&self, height: u32) -> u32 {
        // genesis (height 0) and the first epoch_length blocks after it form epoch 0
        height.saturating_sub(1) / self.epoch_length
    }
    fn select(&self) -> ValidatorSet {
        let mut ranked: Vec<&Candidate> =
            self.candidates.values().filter(|c| c.stake > 0).collect();
        // highest stake first, ties broken by key so the order is deterministic
        ranked.sort_by(|a, b| {
            b.stake
                .cmp(&a.stake)
                .then_with(|| a.validator.id_bytes().cmp(&b.validator.id_bytes()))
        });
        ValidatorSet::new(
            ranked
                .into_iter()
                .take(self.max_validators)
                .map(|c| Validator {
                    weight: c.stake,
                    ..c.validator.clone()
                })
                .collect(),
        )
    }
}

impl<F> ValidatorSetPolicy for EpochStakePolicy<F>
where
    F: FnMut(&Block, &mut BTreeMap<GenericPublicKey, Candidate>) + Send + Sync + 'static,
{
    fn validator_set(&self, height: u32) -> ValidatorSet {
        let epoch = self.epoch_of(height);
        self.epochs
            .range(..=epoch)
            .next_back()
            .map(|(_, set)| set.clone())
            .expect("epoch 0 always exists")
    }
    fn on_block_committed(&mut self, block: &Block) {
        (self.apply_block)(block, &mut self.candidates);
        // the last block of an epoch fixes the set of the next epoch
        if block.height > 0 && block.height.is_multiple_of(self.epoch_length) {
            let next_epoch = block.height / self.epoch_length;
            let set = self.select();
            self.epochs.insert(next_epoch, set);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ecdsa::Keypair, vrf::VrfKeypair};

    fn validator(weight: u64) -> Validator {
        let kp = Keypair::new();
        Validator {
            vrf_key: VrfKeypair::derive_from_ecdsa(&kp.sk).public_bytes(),
            id: kp.vk,
            weight,
            address: String::new(),
        }
    }

    #[test]
    fn quorum_is_more_than_two_thirds() {
        let set = ValidatorSet::new((0..4).map(|_| validator(1)).collect());
        assert!(!set.is_quorum(2));
        assert!(set.is_quorum(3));
        let weighted = ValidatorSet::new(vec![validator(50), validator(30), validator(20)]);
        assert!(!weighted.is_quorum(50 + 20 - 4));
        assert!(weighted.is_quorum(50 + 30));
    }

    #[test]
    fn epoch_stake_policy_rotates_at_epoch_boundaries() {
        let (a, b, c) = (validator(1), validator(1), validator(1));
        let c_id = c.id_bytes();
        // reward rule: proposing a block earns 500 stake
        let apply = |block: &Block, table: &mut BTreeMap<GenericPublicKey, Candidate>| {
            if let Some(cand) = table.get_mut(&block.proposer) {
                cand.stake += 500;
            }
        };
        let mut policy = EpochStakePolicy::new(
            3,
            2,
            vec![
                Candidate {
                    validator: a.clone(),
                    stake: 100,
                },
                Candidate {
                    validator: b.clone(),
                    stake: 90,
                },
                Candidate {
                    validator: c.clone(),
                    stake: 10,
                },
            ],
            apply,
        );
        let ids = |s: ValidatorSet| s.iter().map(|v| v.id_bytes()).collect::<Vec<_>>();
        assert_eq!(
            ids(policy.validator_set(1)),
            vec![a.id_bytes(), b.id_bytes()]
        );
        let block = |height: u32, proposer: &GenericPublicKey| {
            let mut b = Block::genesis(0);
            b.height = height;
            b.proposer = proposer.clone();
            b
        };
        // c proposes during epoch 0 (heights 1..=3)
        policy.on_block_committed(&block(1, &a.id_bytes()));
        policy.on_block_committed(&block(2, &c_id));
        // still epoch 0: no change until the epoch's last block is committed
        assert_eq!(
            ids(policy.validator_set(3)),
            vec![a.id_bytes(), b.id_bytes()]
        );
        policy.on_block_committed(&block(3, &vec![]));
        // epoch 1 (heights 4..=6): c has 510, a 600, b drops out
        let set = policy.validator_set(4);
        assert_eq!(ids(set.clone()), vec![a.id_bytes(), c_id.clone()]);
        assert_eq!(set.get(&c_id).unwrap().weight, 510);
        assert_eq!(
            ids(policy.validator_set(3)),
            vec![a.id_bytes(), b.id_bytes()]
        );
    }
}
