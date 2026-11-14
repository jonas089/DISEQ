//! The consensus state machine of one validator: Tendermint (Buchman, Kwon, Milosevic: "The
//! latest gossip on BFT consensus", 2018) with VRF proposer election, ordering certified
//! batches.
//!
//! * **Propose.** Every validator that is eligible in (height, round) proposes a block listing
//!   certified batches ([`crate::availability`]), attaching a VRF proof. If it already knows a
//!   block that gathered a 2/3+ prevote quorum ("valid value") it re-proposes that instead.
//! * **Prevote.** Once the propose timeout passes, or every validator has proposed, a
//!   validator prevotes for the best proposal it may accept under its lock, or nil. "Best"
//!   means the highest valid round, then the lowest VRF priority.
//! * **Precommit.** On 2/3+ prevotes for a block in its current round it locks on the block and
//!   precommits it. On 2/3+ prevotes for nil, or after the prevote timeout, it precommits nil.
//! * **Commit.** 2/3+ precommits for a block in any round commit it.
//!
//! **Safety** (no two different blocks commit at a height while < 1/3 of the weight is
//! faulty) follows from the lock: a validator that precommitted block B in round r only
//! prevotes for B, or for a block with a newer 2/3+ prevote quorum, in later rounds. Locks and
//! own votes are saved before votes are sent, so a restart cannot cause double signing.
//!
//! **Conflicts.** Two proposals from one proposer in one round: both are dropped and the
//! proposer is ignored for the round. Two votes from one validator for different values: both
//! are kept (see [`VoteBook`]) and a warning is logged. A batch can be committed only once:
//! blocks naming an already committed batch are invalid.
//!
//! The state machine is synchronous and deterministic: inputs are method calls with the
//! current time, outputs are the messages to broadcast ([`Outgoing`]) and committed blocks
//! ([`Consensus::drain_committed`]). Storage goes through [`ConsensusStore`].
use crate::availability::verify_cert;
use crate::config::ConsensusConfig;
use crate::crypto::{
    ecdsa::{try_deserialize_vk, verify_signature},
    vrf, LocalValidator,
};
use crate::election::{self, block_randomness, vrf_input};
use crate::store::ConsensusStore;
use crate::timeouts::Step;
use crate::types::{BatchCert, Block, GenericPublicKey, Hash, Proposal, Vote, VoteKind};
use crate::validators::{ValidatorSet, ValidatorSetPolicy};
use crate::votes::{Received, VoteBook};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

/// Votes and proposals for rounds further ahead than this are dropped (bounds memory).
pub const MAX_ROUNDS_AHEAD: u64 = 16;
/// Verified certificates remembered so re-proposals do not re-check signatures.
const CERT_CACHE: usize = 100_000;

/// Something the validator wants broadcast to its peers.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // short-lived, moved straight into gossip
pub enum Outgoing {
    Proposal(Proposal),
    Vote(Vote),
}

struct ProposalEntry {
    block_hash: Hash,
    valid_round: Option<u64>,
    priority: f64,
}

/// What must survive a restart for a validator to stay safe.
#[derive(Serialize, Deserialize, Default)]
struct PersistedState {
    height: u32,
    round: u64,
    locked: Option<(u64, Hash)>,
    valid: Option<(u64, Hash)>,
    signed: Vec<(VoteKind, u64, Option<Hash>)>,
}

/// Bookkeeping for the height being decided; replaced when it commits.
struct HeightState {
    height: u32,
    round: u64,
    step: Step,
    locked: Option<(u64, Hash)>,
    valid: Option<(u64, Hash)>,
    /// every valid block seen at this height, by hash
    blocks: HashMap<Hash, Block>,
    /// a proposal message carrying each block, for retransmission
    proposal_msgs: HashMap<Hash, Proposal>,
    next_rebroadcast: Option<u64>,
    /// round -> proposer -> proposal
    proposals: HashMap<u64, HashMap<GenericPublicKey, ProposalEntry>>,
    equivocators: HashSet<(u64, GenericPublicKey)>,
    votes: VoteBook,
    /// own signed votes
    signed: HashMap<(VoteKind, u64), Option<Hash>>,
    proposed_rounds: HashSet<u64>,
    polka_handled: HashSet<u64>,
    propose_deadline: Option<u64>,
    prevote_deadline: Option<u64>,
    precommit_deadline: Option<u64>,
}

impl HeightState {
    fn new(height: u32) -> Self {
        HeightState {
            height,
            round: 0,
            step: Step::Propose,
            locked: None,
            valid: None,
            blocks: HashMap::new(),
            proposal_msgs: HashMap::new(),
            next_rebroadcast: None,
            proposals: HashMap::new(),
            equivocators: HashSet::new(),
            votes: VoteBook::default(),
            signed: HashMap::new(),
            proposed_rounds: HashSet::new(),
            polka_handled: HashSet::new(),
            propose_deadline: None,
            prevote_deadline: None,
            precommit_deadline: None,
        }
    }
}

/// Certified batches not yet in a committed block, in arrival order.
#[derive(Default)]
struct PendingBatches {
    order: VecDeque<Hash>,
    certs: HashMap<Hash, BatchCert>,
}

impl PendingBatches {
    /// Oldest certificates within the block limits.
    fn take(&self, max_messages: u64, max_batches: usize) -> Vec<BatchCert> {
        let mut out = Vec::new();
        let mut messages = 0u64;
        for cert in self.order.iter().filter_map(|d| self.certs.get(d)) {
            if out.len() == max_batches || messages + cert.messages as u64 > max_messages {
                break;
            }
            messages += cert.messages as u64;
            out.push(cert.clone());
        }
        out
    }
    fn remove(&mut self, digests: impl Iterator<Item = Hash>) {
        for d in digests {
            self.certs.remove(&d);
        }
        while self
            .order
            .front()
            .is_some_and(|d| !self.certs.contains_key(d))
        {
            self.order.pop_front();
        }
        if self.order.len() > 2 * self.certs.len() + 1024 {
            let certs = &self.certs;
            self.order.retain(|d| certs.contains_key(d));
        }
    }
}

pub struct Consensus<S: ConsensusStore> {
    config: ConsensusConfig,
    store: S,
    policy: Box<dyn ValidatorSetPolicy>,
    identity: Option<LocalValidator>,
    /// last committed block (the parent of the height being decided)
    last: Block,
    hs: HeightState,
    pending: PendingBatches,
    verified_certs: HashSet<Hash>,
    outbox: Vec<Outgoing>,
    committed: Vec<Block>,
    now_ms: u64,
}

impl<S: ConsensusStore> Consensus<S> {
    pub fn new(
        config: ConsensusConfig,
        mut store: S,
        mut policy: Box<dyn ValidatorSetPolicy>,
        identity: Option<LocalValidator>,
    ) -> Result<Self> {
        config.validate();
        let genesis = Block::genesis(config.genesis_timestamp);
        match store.block(0)? {
            Some(existing) => ensure!(
                existing.hash() == genesis.hash(),
                "database contains a different genesis block"
            ),
            None => store.commit_block(&genesis)?,
        }
        // rebuild policy state (e.g. stake tables) from the committed chain
        let latest = store.latest_height()?;
        let mut last = genesis;
        for height in 1..=latest {
            last = store.block(height)?.context("gap in stored chain")?;
            policy.on_block_committed(&last);
        }
        let mut hs = HeightState::new(latest + 1);
        // restore locks and own votes for the height in progress
        if let Some(bytes) = store.load_state()? {
            let persisted: PersistedState = bincode::deserialize(&bytes)?;
            if persisted.height == hs.height {
                hs.round = persisted.round;
                hs.locked = persisted.locked;
                hs.valid = persisted.valid;
                hs.signed = persisted
                    .signed
                    .into_iter()
                    .map(|(kind, round, hash)| ((kind, round), hash))
                    .collect();
            }
        }
        Ok(Consensus {
            config,
            store,
            policy,
            identity,
            last,
            hs,
            pending: PendingBatches::default(),
            verified_certs: HashSet::new(),
            outbox: Vec::new(),
            committed: Vec::new(),
            now_ms: 0,
        })
    }

    // ---- queries ----------------------------------------------------------------------------

    pub fn local_id(&self) -> Option<GenericPublicKey> {
        self.identity.as_ref().map(|i| i.id())
    }

    pub fn identity(&self) -> Option<&LocalValidator> {
        self.identity.as_ref()
    }

    pub fn validator_set(&self, height: u32) -> ValidatorSet {
        self.policy.validator_set(height)
    }

    /// The validator set of the height being decided.
    pub fn current_validators(&self) -> ValidatorSet {
        self.validator_set(self.hs.height)
    }

    /// Current (height, round, step).
    pub fn position(&self) -> (u32, u64, Step) {
        (self.hs.height, self.hs.round, self.hs.step)
    }

    pub fn last_block(&self) -> &Block {
        &self.last
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// The block this validator is locked on, if any: (round, hash).
    pub fn locked(&self) -> Option<(u64, Hash)> {
        self.hs.locked
    }

    pub fn pending_batches(&self) -> usize {
        self.pending.certs.len()
    }

    /// Committed blocks since the last call, in height order.
    pub fn drain_committed(&mut self) -> Vec<Block> {
        std::mem::take(&mut self.committed)
    }

    /// Human readable consensus state, for debugging.
    pub fn debug_state(&self) -> String {
        let set = self.current_validators();
        let mut keys: Vec<_> = self.hs.votes.iter().map(|(k, _)| *k).collect();
        keys.sort();
        let votes: Vec<String> = keys
            .into_iter()
            .map(|(kind, round)| {
                let t: Vec<String> = self
                    .hs
                    .votes
                    .tally(&set, kind, round)
                    .iter()
                    .map(|(h, w)| {
                        format!("{}:{w}", h.map_or("nil".into(), |h| hex::encode(&h[..3])))
                    })
                    .collect();
                format!("{kind:?}@{round}[{}]", t.join(","))
            })
            .collect();
        format!(
            "h={} r={} step={:?} locked={:?} valid={:?} now={} pending_batches={} signed={:?} votes={}",
            self.hs.height,
            self.hs.round,
            self.hs.step,
            self.hs.locked.map(|(r, h)| (r, hex::encode(&h[..3]))),
            self.hs.valid.map(|(r, h)| (r, hex::encode(&h[..3]))),
            self.now_ms,
            self.pending.certs.len(),
            self.hs.signed.keys().collect::<Vec<_>>(),
            votes.join(" ")
        )
    }

    // ---- inputs -----------------------------------------------------------------------------

    /// Adds a certified batch to the queue of batches to propose.
    pub fn add_certificate(&mut self, cert: BatchCert) -> Result<Received> {
        if self.pending.certs.contains_key(&cert.digest) {
            return Ok(Received::Duplicate);
        }
        if self.store.batches_committed(&[cert.digest])?[0] {
            return Ok(Received::Duplicate);
        }
        ensure!(
            self.pending.certs.len() < self.config.max_pending_batches,
            "too many pending batches"
        );
        self.check_cert(&cert, &self.current_validators())?;
        self.pending.order.push_back(cert.digest);
        self.pending.certs.insert(cert.digest, cert);
        Ok(Received::New)
    }

    /// Drives proposing and timeouts from the local clock (milliseconds).
    pub fn on_tick(&mut self, now_ms: u64) -> Result<Vec<Outgoing>> {
        self.now_ms = now_ms;
        let round = self.hs.round;
        if self.hs.step == Step::Propose {
            let deadline = *self
                .hs
                .propose_deadline
                .get_or_insert(now_ms + self.config.timing.propose(round));
            self.maybe_propose()?;
            if now_ms >= deadline {
                self.on_propose_timeout()?;
            }
        }
        if self.hs.step == Step::Prevote && self.hs.prevote_deadline.is_some_and(|d| now_ms >= d) {
            self.cast(VoteKind::Precommit, round, None)?;
            self.hs.step = Step::Precommit;
        }
        if self.hs.precommit_deadline.is_some_and(|d| now_ms >= d) {
            self.start_round(round + 1);
        }
        self.process()?;
        self.maybe_rebroadcast();
        Ok(std::mem::take(&mut self.outbox))
    }

    /// Handles a proposal received from a peer.
    pub fn on_proposal(
        &mut self,
        proposal: Proposal,
        now_ms: u64,
    ) -> Result<(Received, Vec<Outgoing>)> {
        self.now_ms = now_ms;
        let height = self.hs.height;
        if proposal.height < height {
            return Ok((Received::Duplicate, Vec::new()));
        }
        ensure!(
            proposal.height == height,
            "proposal for future height {}",
            proposal.height
        );
        ensure!(
            proposal.round <= self.hs.round + MAX_ROUNDS_AHEAD,
            "proposal round {} too far ahead",
            proposal.round
        );
        if let Some(vr) = proposal.valid_round {
            ensure!(
                vr < proposal.round,
                "valid round must precede the proposal round"
            );
        }
        ensure!(proposal.block.height == height, "block height mismatch");
        let key = (proposal.round, proposal.proposer.clone());
        ensure!(
            !self.hs.equivocators.contains(&key),
            "proposer equivocated in this round"
        );
        let block_hash = proposal.block.hash();
        if let Some(existing) = self
            .hs
            .proposals
            .get(&proposal.round)
            .and_then(|p| p.get(&proposal.proposer))
        {
            if existing.block_hash == block_hash && existing.valid_round == proposal.valid_round {
                return Ok((Received::Duplicate, Vec::new()));
            }
            // two different proposals from one proposer in one round: drop both
            if let Some(p) = self.hs.proposals.get_mut(&proposal.round) {
                p.remove(&proposal.proposer);
            }
            self.hs.equivocators.insert(key);
            bail!("proposer equivocated in round {}", proposal.round);
        }

        let set = self.current_validators();
        let proposer = set
            .get(&proposal.proposer)
            .ok_or_else(|| anyhow!("proposer is not an active validator"))?;
        let input = vrf_input(&block_randomness(&self.last), height, proposal.round);
        let output = vrf::verify(&proposer.vrf_key, &input, &proposal.vrf)?;
        ensure!(
            election::is_eligible(
                &output,
                proposer.weight,
                set.total_weight(),
                self.config.expected_proposers
            ),
            "proposer is not eligible in this round"
        );
        verify_signature(
            &proposer.id,
            &Proposal::signing_payload(height, proposal.round, proposal.valid_round, &block_hash),
            &proposal.signature,
        )?;
        let priority = election::priority(&output, proposer.weight);
        if !self.hs.blocks.contains_key(&block_hash) {
            self.verify_block(&proposal.block, &set, Some((now_ms / 1000) as u32))?;
            self.hs.blocks.insert(block_hash, proposal.block.clone());
        }
        self.hs
            .proposal_msgs
            .entry(block_hash)
            .or_insert_with(|| proposal.clone());
        self.hs.proposals.entry(proposal.round).or_default().insert(
            proposal.proposer,
            ProposalEntry {
                block_hash,
                valid_round: proposal.valid_round,
                priority,
            },
        );
        self.process()?;
        Ok((Received::New, std::mem::take(&mut self.outbox)))
    }

    /// Handles a vote received from a peer.
    pub fn on_vote(&mut self, vote: Vote, now_ms: u64) -> Result<(Received, Vec<Outgoing>)> {
        self.now_ms = now_ms;
        let height = self.hs.height;
        if vote.height < height {
            return Ok((Received::Duplicate, Vec::new()));
        }
        ensure!(
            vote.height == height,
            "vote for future height {}",
            vote.height
        );
        ensure!(
            vote.round <= self.hs.round + MAX_ROUNDS_AHEAD,
            "vote round {} too far ahead",
            vote.round
        );
        let set = self.current_validators();
        let validator = set
            .get(&vote.validator)
            .ok_or_else(|| anyhow!("vote from unknown validator"))?;
        verify_signature(
            &validator.id,
            &Vote::signing_payload(vote.kind, vote.height, vote.round, &vote.block_hash),
            &vote.signature,
        )?;
        let received = self.record_vote(vote)?;
        if received == Received::New {
            self.process()?;
        }
        Ok((received, std::mem::take(&mut self.outbox)))
    }

    /// Validates and commits a certified block fetched from a peer during sync.
    pub fn on_certified_block(&mut self, block: Block) -> Result<()> {
        ensure!(
            block.height == self.last.height + 1,
            "expected block {}, got {}",
            self.last.height + 1,
            block.height
        );
        let set = self.current_validators();
        self.verify_block(&block, &set, None)?;
        let hash = block.hash();
        let round = block
            .votes
            .first()
            .map(|v| v.round)
            .ok_or_else(|| anyhow!("block has no commit certificate"))?;
        let mut seen = HashSet::new();
        let mut weight = 0u64;
        for vote in &block.votes {
            ensure!(
                vote.kind == VoteKind::Precommit
                    && vote.height == block.height
                    && vote.round == round
                    && vote.block_hash == Some(hash),
                "vote does not match block"
            );
            ensure!(seen.insert(vote.validator.clone()), "duplicate vote");
            let validator = set
                .get(&vote.validator)
                .ok_or_else(|| anyhow!("vote from unknown validator"))?;
            verify_signature(
                &validator.id,
                &Vote::signing_payload(vote.kind, vote.height, vote.round, &vote.block_hash),
                &vote.signature,
            )?;
            weight += validator.weight;
        }
        ensure!(set.is_quorum(weight), "block lacks a quorum of precommits");
        self.commit(block)
    }

    // ---- rules ------------------------------------------------------------------------------

    fn active_weight(&self) -> Option<u64> {
        let id = self.local_id()?;
        self.current_validators().get(&id).map(|v| v.weight)
    }

    fn start_round(&mut self, round: u64) {
        self.hs.round = round;
        self.hs.step = Step::Propose;
        self.hs.propose_deadline = Some(self.now_ms + self.config.timing.propose(round));
        self.hs.prevote_deadline = None;
        self.hs.precommit_deadline = None;
    }

    fn maybe_propose(&mut self) -> Result<()> {
        let round = self.hs.round;
        let height = self.hs.height;
        let Some(weight) = self.active_weight() else {
            return Ok(());
        };
        if self.hs.proposed_rounds.contains(&round) {
            return Ok(());
        }
        let identity = self.identity.as_ref().expect("active validator has keys");
        let set = self.current_validators();
        let input = vrf_input(&block_randomness(&self.last), height, round);
        let (output, claim) = identity.vrf.prove(&input);
        if !election::is_eligible(
            &output,
            weight,
            set.total_weight(),
            self.config.expected_proposers,
        ) {
            self.hs.proposed_rounds.insert(round);
            return Ok(());
        }
        let (block, valid_round) = match self.hs.valid {
            Some((vr, hash)) => (self.hs.blocks[&hash].clone(), Some(vr)),
            None => {
                let batches = self.pending.take(
                    self.config.max_block_messages,
                    self.config.max_block_batches,
                );
                if batches.is_empty() && !self.config.allow_empty_blocks {
                    // nothing to order yet; try again on the next tick of this round
                    return Ok(());
                }
                let mut block = Block {
                    height,
                    round,
                    parent_hash: self.last.hash(),
                    proposer: identity.id(),
                    vrf: Some(claim.clone()),
                    batches,
                    timestamp: ((self.now_ms / 1000) as u32).max(self.last.timestamp),
                    signature: None,
                    votes: Vec::new(),
                };
                block.signature = Some(identity.sign(&Block::signing_payload(&block.hash())));
                (block, None)
            }
        };
        self.hs.proposed_rounds.insert(round);
        let block_hash = block.hash();
        let proposal = Proposal {
            height,
            round,
            valid_round,
            proposer: identity.id(),
            vrf: claim,
            signature: identity.sign(&Proposal::signing_payload(
                height,
                round,
                valid_round,
                &block_hash,
            )),
            block: block.clone(),
        };
        self.hs.blocks.insert(block_hash, block);
        self.hs.proposal_msgs.insert(block_hash, proposal.clone());
        self.hs.proposals.entry(round).or_default().insert(
            proposal.proposer.clone(),
            ProposalEntry {
                block_hash,
                valid_round,
                priority: election::priority(&output, weight),
            },
        );
        self.outbox.push(Outgoing::Proposal(proposal));
        Ok(())
    }

    /// Re-sends own votes of this height and the proposals behind the blocks they name.
    fn maybe_rebroadcast(&mut self) {
        let interval = self.config.timing.rebroadcast_interval_ms;
        let due = *self
            .hs
            .next_rebroadcast
            .get_or_insert(self.now_ms + interval);
        if self.now_ms < due {
            return;
        }
        self.hs.next_rebroadcast = Some(self.now_ms + interval);
        let Some(me) = self.local_id() else {
            return;
        };
        let mut hashes = BTreeSet::new();
        let mut votes: Vec<Vote> = self
            .hs
            .votes
            .iter()
            .flat_map(|(_, v)| v.iter().filter(|vote| vote.validator == me).cloned())
            .collect();
        votes.sort_by_key(|v| (v.round, v.kind));
        for vote in &votes {
            if let Some(h) = vote.block_hash {
                hashes.insert(h);
            }
        }
        // own proposal(s) as well, so a lost proposal does not cost the round
        for (hash, p) in &self.hs.proposal_msgs {
            if p.proposer == me {
                hashes.insert(*hash);
            }
        }
        for hash in hashes {
            if let Some(p) = self.hs.proposal_msgs.get(&hash) {
                self.outbox.push(Outgoing::Proposal(p.clone()));
            }
        }
        // the prevotes justifying our valid value: peers need them to accept its
        // re-proposal, and may have seen conflicting votes from an equivocator instead
        if let Some((vr, hash)) = self.hs.valid {
            votes.extend(
                self.hs
                    .votes
                    .get(VoteKind::Prevote, vr)
                    .iter()
                    .filter(|v| v.block_hash == Some(hash) && v.validator != me)
                    .cloned(),
            );
        }
        self.outbox.extend(votes.into_iter().map(Outgoing::Vote));
    }

    /// May this validator prevote for `block_hash` proposed with `valid_round` in `round`?
    fn acceptable(&self, round: u64, block_hash: &Hash, valid_round: Option<u64>) -> bool {
        match valid_round {
            None => self
                .hs
                .locked
                .is_none_or(|(_, locked)| locked == *block_hash),
            Some(vr) => {
                vr < round
                    && self.hs.votes.has_quorum(
                        &self.current_validators(),
                        VoteKind::Prevote,
                        vr,
                        Some(*block_hash),
                    )
                    && self
                        .hs
                        .locked
                        .is_none_or(|(lr, locked)| lr <= vr || locked == *block_hash)
            }
        }
    }

    /// With every validator a candidate, once all have proposed no better proposal can come:
    /// prevote now instead of waiting out the propose timeout.
    fn everyone_proposed(&self) -> bool {
        if self.config.expected_proposers.is_some() {
            return false;
        }
        let set = self.current_validators();
        let proposed: u64 = self
            .hs
            .proposals
            .get(&self.hs.round)
            .map(|p| {
                p.keys()
                    .filter_map(|id| set.get(id))
                    .map(|v| v.weight)
                    .sum()
            })
            .unwrap_or(0);
        proposed == set.total_weight()
    }

    fn on_propose_timeout(&mut self) -> Result<()> {
        let round = self.hs.round;
        let best = self.hs.proposals.get(&round).and_then(|proposals| {
            proposals
                .values()
                .filter(|p| self.acceptable(round, &p.block_hash, p.valid_round))
                // Re-proposals backed by the most recent 2/3+ prevote quorum come first: locked
                // validators can only vote for those, so preferring fresh blocks with a better
                // VRF priority could split the honest votes forever. VRF priority breaks ties.
                .min_by(|a, b| {
                    b.valid_round.cmp(&a.valid_round).then_with(|| {
                        election::compare((a.priority, &a.block_hash), (b.priority, &b.block_hash))
                    })
                })
                .map(|p| p.block_hash)
        });
        let idle = self.hs.proposals.get(&round).is_none_or(|p| p.is_empty())
            && self.hs.valid.is_none()
            && !self.config.allow_empty_blocks
            && self.pending.certs.is_empty();
        if best.is_none() && idle {
            // nothing anywhere to order: wait instead of burning rounds on nil votes
            self.hs.propose_deadline = Some(self.now_ms + self.config.timing.propose(round));
            return Ok(());
        }
        self.cast(VoteKind::Prevote, round, best)?;
        self.hs.step = Step::Prevote;
        Ok(())
    }

    /// Re-evaluates the vote-driven rules until nothing changes.
    fn process(&mut self) -> Result<()> {
        loop {
            let set = self.current_validators();

            // commit: 2/3+ precommits for a block we know, in any round
            let commit = self.hs.votes.iter().find_map(|((kind, round), votes)| {
                if *kind != VoteKind::Precommit {
                    return None;
                }
                crate::votes::tally(&set, votes)
                    .into_iter()
                    .find(|(hash, w)| {
                        set.is_quorum(*w) && hash.is_some_and(|h| self.hs.blocks.contains_key(&h))
                    })
                    .map(|(hash, _)| (*round, hash.expect("checked")))
            });
            if let Some((round, hash)) = commit {
                let mut block = self.hs.blocks[&hash].clone();
                block.votes = self
                    .hs
                    .votes
                    .get(VoteKind::Precommit, round)
                    .iter()
                    .filter(|v| v.block_hash == Some(hash))
                    .cloned()
                    .collect();
                return self.commit(block);
            }

            // round skip: > 1/3 of the weight is already in a later round
            let skip_to = self
                .hs
                .votes
                .later_rounds(self.hs.round)
                .into_iter()
                .filter(|r| {
                    (self.hs.votes.round_weight(&set, *r) as u128) * 3 > set.total_weight() as u128
                })
                .max();
            if let Some(round) = skip_to {
                self.start_round(round);
                continue;
            }

            if self.hs.step == Step::Propose && self.everyone_proposed() {
                self.on_propose_timeout()?;
                if self.hs.step == Step::Prevote {
                    continue;
                }
            }

            let round = self.hs.round;
            let prevotes = self.hs.votes.tally(&set, VoteKind::Prevote, round);

            // polka for a block in the current round: lock and precommit
            if self.hs.step >= Step::Prevote && !self.hs.polka_handled.contains(&round) {
                let polka = prevotes.iter().find(|(hash, w)| {
                    set.is_quorum(**w) && hash.is_some_and(|h| self.hs.blocks.contains_key(&h))
                });
                if let Some((Some(hash), _)) = polka {
                    let hash = *hash;
                    self.hs.polka_handled.insert(round);
                    self.hs.valid = Some((round, hash));
                    if self.hs.step == Step::Prevote {
                        self.hs.locked = Some((round, hash));
                        self.cast(VoteKind::Precommit, round, Some(hash))?;
                        self.hs.step = Step::Precommit;
                    } else {
                        self.persist()?;
                    }
                    continue;
                }
            }

            // polka for nil
            if self.hs.step == Step::Prevote
                && prevotes.get(&None).is_some_and(|w| set.is_quorum(*w))
            {
                self.cast(VoteKind::Precommit, round, None)?;
                self.hs.step = Step::Precommit;
                continue;
            }

            // timeouts once 2/3+ of the weight has voted without agreement
            if self.hs.step == Step::Prevote
                && self.hs.prevote_deadline.is_none()
                && set.is_quorum(self.hs.votes.voters_weight(&set, VoteKind::Prevote, round))
            {
                self.hs.prevote_deadline = Some(self.now_ms + self.config.timing.prevote(round));
            }
            if self.hs.precommit_deadline.is_none()
                && set.is_quorum(
                    self.hs
                        .votes
                        .voters_weight(&set, VoteKind::Precommit, round),
                )
            {
                self.hs.precommit_deadline =
                    Some(self.now_ms + self.config.timing.precommit(round));
            }
            return Ok(());
        }
    }

    /// Signs, persists, records and queues an own vote (at most one per kind and round).
    fn cast(&mut self, kind: VoteKind, round: u64, block_hash: Option<Hash>) -> Result<()> {
        if self.active_weight().is_none() || self.hs.signed.contains_key(&(kind, round)) {
            return Ok(());
        }
        let identity = self.identity.as_ref().expect("active validator has keys");
        let height = self.hs.height;
        let vote = Vote {
            kind,
            height,
            round,
            block_hash,
            validator: identity.id(),
            signature: identity.sign(&Vote::signing_payload(kind, height, round, &block_hash)),
        };
        self.hs.signed.insert((kind, round), block_hash);
        // persist before the vote can leave this node
        self.persist()?;
        self.record_vote(vote.clone())?;
        self.outbox.push(Outgoing::Vote(vote));
        Ok(())
    }

    fn persist(&mut self) -> Result<()> {
        let state = PersistedState {
            height: self.hs.height,
            round: self.hs.round,
            locked: self.hs.locked,
            valid: self.hs.valid,
            signed: self
                .hs
                .signed
                .iter()
                .map(|((kind, round), hash)| (*kind, *round, *hash))
                .collect(),
        };
        self.store.save_state(&bincode::serialize(&state)?)
    }

    fn record_vote(&mut self, vote: Vote) -> Result<Received> {
        let known = vote
            .block_hash
            .is_none_or(|h| self.hs.blocks.contains_key(&h));
        self.hs.votes.record(vote, known)
    }

    /// Verifies a certificate, skipping signatures of an identical one verified before.
    fn check_cert(&mut self, cert: &BatchCert, set: &ValidatorSet) -> Result<()> {
        let id = cert.hash();
        if self.verified_certs.contains(&id) {
            return Ok(());
        }
        verify_cert(cert, set)?;
        if self.verified_certs.len() >= CERT_CACHE {
            self.verified_certs.clear();
        }
        self.verified_certs.insert(id);
        Ok(())
    }

    /// Checks a block's own validity (author, VRF, signature, batches); not its votes.
    fn verify_block(
        &mut self,
        block: &Block,
        set: &ValidatorSet,
        now_secs: Option<u32>,
    ) -> Result<()> {
        let parent = &self.last;
        ensure!(block.height == parent.height + 1, "wrong height");
        ensure!(block.parent_hash == parent.hash(), "wrong parent hash");
        let author = set
            .get(&block.proposer)
            .ok_or_else(|| anyhow!("block author is not an active validator"))?;
        let claim = block
            .vrf
            .as_ref()
            .ok_or_else(|| anyhow!("missing VRF proof"))?;
        let input = vrf_input(&block_randomness(parent), block.height, block.round);
        let output = vrf::verify(&author.vrf_key, &input, claim)?;
        ensure!(
            election::is_eligible(
                &output,
                author.weight,
                set.total_weight(),
                self.config.expected_proposers
            ),
            "block author was not eligible in its round"
        );
        let signature = block
            .signature
            .as_ref()
            .ok_or_else(|| anyhow!("block is not signed"))?;
        verify_signature(
            &try_deserialize_vk(&block.proposer)?,
            &Block::signing_payload(&block.hash()),
            signature,
        )?;
        ensure!(
            block.timestamp >= parent.timestamp,
            "timestamp before parent"
        );
        if let Some(now) = now_secs {
            ensure!(
                block.timestamp as u64 <= now as u64 + self.config.timing.max_clock_drift as u64,
                "timestamp is in the future"
            );
        }
        ensure!(
            block.batches.len() <= self.config.max_block_batches
                && block.message_count() <= self.config.max_block_messages,
            "block exceeds size limits"
        );
        let digests: Vec<Hash> = block.batches.iter().map(|b| b.digest).collect();
        ensure!(
            digests.iter().collect::<HashSet<_>>().len() == digests.len(),
            "batch listed twice"
        );
        ensure!(
            !self
                .store
                .batches_committed(&digests)?
                .into_iter()
                .any(|c| c),
            "batch was already committed"
        );
        for cert in &block.batches {
            self.check_cert(cert, set)?;
        }
        Ok(())
    }

    fn commit(&mut self, block: Block) -> Result<()> {
        self.store.commit_block(&block)?;
        let set_before = self.current_validators();
        self.pending.remove(block.batches.iter().map(|b| b.digest));
        self.policy.on_block_committed(&block);
        let commit_round = block.votes.first().map_or(0, |v| v.round);
        self.hs = HeightState::new(block.height + 1);
        let set = self.current_validators();
        if set != set_before {
            // certificates are only valid relative to a validator set: drop queued ones the
            // new set does not certify (their authors re-collect attestations)
            self.verified_certs.clear();
            let old = std::mem::take(&mut self.pending);
            for digest in old.order {
                if let Some(cert) = old.certs.get(&digest) {
                    if verify_cert(cert, &set).is_ok() && !self.pending.certs.contains_key(&digest)
                    {
                        self.pending.order.push_back(digest);
                        self.pending.certs.insert(digest, cert.clone());
                    }
                }
            }
        }
        self.start_round(0);
        self.persist()?;
        crate::log_info(format!(
            "Committed block {} (round {commit_round}, {} batches, {} messages, {} precommits), hash {}",
            block.height,
            block.batches.len(),
            block.message_count(),
            block.votes.len(),
            hex::encode(block.hash())
        ));
        self.last = block.clone();
        self.committed.push(block);
        Ok(())
    }
}
