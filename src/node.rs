//! Consensus and mempool state machine of a single node.
//!
//! Consensus follows Tendermint (Buchman, Kwon, Milosevic: "The latest gossip on BFT
//! consensus", 2018) with VRF based proposer election:
//!
//! * **Propose.** Every validator that is eligible in (height, round) proposes, attaching a
//!   VRF proof. If it already knows a block that gathered a 2/3+ prevote quorum ("valid
//!   value") it re-proposes that block instead of a new one.
//! * **Prevote.** After the propose timeout a validator prevotes for the best proposal it is
//!   allowed to accept under its lock, or nil. "Best" means the highest valid round (a block
//!   that already had a 2/3+ prevote quorum), then the lowest VRF priority.
//! * **Precommit.** On 2/3+ prevotes for a block in its current round it locks on the block and
//!   precommits it. On 2/3+ prevotes for nil, or after the prevote timeout, it precommits nil.
//! * **Commit.** 2/3+ precommits for a block in any round commit it.
//!
//! Safety (no two different blocks commit at a height while < 1/3 of the weight is faulty)
//! follows from the lock: a validator that precommitted block B in round r only prevotes for
//! B, or for a block that has a newer 2/3+ prevote quorum, in later rounds. Locks and own
//! votes are persisted before they are sent, so a restart cannot cause double signing.
//!
//! All methods are synchronous and do no networking; they return the messages the caller
//! should broadcast.
use crate::config::node::NodeConfig;
use crate::consensus::election::{self, block_randomness, vrf_input};
use crate::consensus::logic::Step;
use crate::consensus::validators::{ValidatorSet, ValidatorSetPolicy};
use crate::crypto::ecdsa::{try_deserialize_vk, verify_signature};
use crate::crypto::vrf::{self, VrfKeypair};
use crate::state::server::Store;
use crate::types::{
    message_leaf, Block, GenericPublicKey, Hash, Message, Proposal, Vote, VoteKind,
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use ciphercurve_trie::{
    insert_leaf,
    merkle::{merkle_proof, MerkleProof},
    store::{
        db::sql::TrieDB,
        types::{Node as TrieNode, Root},
    },
};
use colored::Colorize;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Votes and proposals for rounds further ahead than this are dropped (bounds memory).
pub const MAX_ROUNDS_AHEAD: u64 = 16;
const CONSENSUS_STATE_KEY: &str = "consensus_state";

/// Keys of the validator this node runs as.
pub struct LocalValidator {
    pub signing_key: SigningKey,
    pub vrf: VrfKeypair,
}
impl LocalValidator {
    /// Uses the VRF key derived from the ECDSA key (matches the default validator set).
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let vrf = VrfKeypair::derive_from_ecdsa(&signing_key);
        LocalValidator { signing_key, vrf }
    }
    pub fn id(&self) -> GenericPublicKey {
        self.signing_key.verifying_key().to_sec1_bytes().to_vec()
    }
    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(payload);
        signature.to_bytes().to_vec()
    }
}

/// Something the node wants broadcast to its peers.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // short-lived, moved straight into gossip
pub enum Outgoing {
    Proposal(Proposal),
    Vote(Vote),
}

/// Whether an incoming item was new (and should be relayed) or already known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    New,
    Duplicate,
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

/// Consensus bookkeeping for the height being decided; replaced when it commits.
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
    /// (kind, round) -> validator -> vote
    /// (kind, round) -> votes, unique per (validator, value). An equivocating validator can
    /// appear once per value it signed: its vote then counts toward each of those values,
    /// which is safe (safety only relies on honest validators) and needed for liveness, since
    /// different honest nodes may have seen different votes from it.
    votes: HashMap<(VoteKind, u64), Vec<Vote>>,
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
            votes: HashMap::new(),
            signed: HashMap::new(),
            proposed_rounds: HashSet::new(),
            polka_handled: HashSet::new(),
            propose_deadline: None,
            prevote_deadline: None,
            precommit_deadline: None,
        }
    }
}

pub struct Node {
    pub config: NodeConfig,
    pub store: Store,
    trie: TrieDB,
    trie_root: Root,
    policy: Box<dyn ValidatorSetPolicy>,
    identity: Option<LocalValidator>,
    hs: HeightState,
    outbox: Vec<Outgoing>,
    now_ms: u64,
}

pub fn log_info(msg: impl std::fmt::Display) {
    println!("{} {}", "[Info]".green(), msg);
}
pub fn log_warn(msg: impl std::fmt::Display) {
    println!("{} {}", "[Warning]".yellow(), msg);
}

impl Node {
    pub fn new(
        config: NodeConfig,
        mut policy: Box<dyn ValidatorSetPolicy>,
        identity: Option<LocalValidator>,
    ) -> Result<Self> {
        config.timing.validate();
        let store = Store::open(&config.db_path)?;
        store.init_genesis(&Block::genesis(config.genesis_timestamp))?;
        let trie = TrieDB {
            path: config.db_path.clone(),
            cache: None,
        };
        trie.setup();
        let trie_root = store.trie_root()?;
        // rebuild policy state (e.g. stake tables) from the committed chain
        let latest = store.latest_height()?;
        for height in 1..=latest {
            let block = store.block(height)?.context("gap in stored chain")?;
            policy.on_block_committed(&block);
        }
        let mut hs = HeightState::new(latest + 1);
        // restore locks and own votes for the height in progress
        if let Some(bytes) = store.meta_get(CONSENSUS_STATE_KEY)? {
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
        Ok(Node {
            config,
            store,
            trie,
            trie_root,
            policy,
            identity,
            hs,
            outbox: Vec::new(),
            now_ms: 0,
        })
    }

    pub fn local_id(&self) -> Option<GenericPublicKey> {
        self.identity.as_ref().map(|i| i.id())
    }

    pub fn validator_set(&self, height: u32) -> ValidatorSet {
        self.policy.validator_set(height)
    }

    /// Current (height, round, step), for observability and tests.
    pub fn consensus_position(&self) -> (u32, u64, Step) {
        (self.hs.height, self.hs.round, self.hs.step)
    }

    /// The block this validator is locked on, if any: (round, hash).
    pub fn locked(&self) -> Option<(u64, Hash)> {
        self.hs.locked
    }

    /// Human readable consensus state (for debugging and the `/get/consensus` endpoint).
    pub fn debug_state(&self) -> String {
        let set = self.validator_set(self.hs.height);
        let mut rounds: Vec<_> = self.hs.votes.keys().collect();
        rounds.sort();
        let votes: Vec<String> = rounds
            .into_iter()
            .map(|(kind, round)| {
                let t = tally(&set, &self.hs.votes[&(*kind, *round)]);
                let t: Vec<String> = t
                    .iter()
                    .map(|(h, w)| {
                        format!("{}:{w}", h.map_or("nil".into(), |h| hex::encode(&h[..3])))
                    })
                    .collect();
                format!("{kind:?}@{round}[{}]", t.join(","))
            })
            .collect();
        format!(
            "h={} r={} step={:?} locked={:?} valid={:?} now={} deadlines(propose={:?}, prevote={:?}, precommit={:?}) signed={:?} votes={}",
            self.hs.height,
            self.hs.round,
            self.hs.step,
            self.hs.locked.map(|(r, h)| (r, hex::encode(&h[..3]))),
            self.hs.valid.map(|(r, h)| (r, hex::encode(&h[..3]))),
            self.now_ms,
            self.hs.propose_deadline,
            self.hs.prevote_deadline,
            self.hs.precommit_deadline,
            self.hs.signed.keys().collect::<Vec<_>>(),
            votes.join(" ")
        )
    }

    /// Gossip targets: the validators of the next height (minus self) and any extra peers.
    pub fn peers(&self) -> Result<Vec<String>> {
        let me = self.local_id();
        let mut peers: Vec<String> = self
            .validator_set(self.hs.height)
            .iter()
            .filter(|v| Some(v.id_bytes()) != me)
            .map(|v| v.address.clone())
            .chain(self.config.extra_peers.iter().cloned())
            .filter(|a| *a != self.config.listen_addr)
            .collect();
        peers.sort();
        peers.dedup();
        Ok(peers)
    }

    pub fn trie_root(&self) -> &Root {
        &self.trie_root
    }

    pub fn merkle_proof(&mut self, key: Vec<u8>) -> Result<MerkleProof> {
        merkle_proof(&mut self.trie, key, TrieNode::Root(self.trie_root.clone()))
    }

    // ---- mempool ------------------------------------------------------------------------

    /// Adds a message to the mempool. Returns `New` if it should be relayed to peers.
    pub fn submit_message(&mut self, message: &Message) -> Result<Received> {
        ensure!(!message.data.is_empty(), "empty message");
        ensure!(
            message.data.len() <= self.config.max_message_bytes,
            "message exceeds {} bytes",
            self.config.max_message_bytes
        );
        Ok(
            if self.store.pool_insert(message, self.config.max_pool_size)? {
                Received::New
            } else {
                Received::Duplicate
            },
        )
    }

    // ---- consensus inputs ---------------------------------------------------------------

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

        let set = self.validator_set(height);
        let parent = self.store.latest_block()?;
        let proposer = set
            .get(&proposal.proposer)
            .ok_or_else(|| anyhow!("proposer is not an active validator"))?;
        let input = vrf_input(&block_randomness(&parent), height, proposal.round);
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
            self.verify_block(&proposal.block, &parent, &set, Some((now_ms / 1000) as u32))?;
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
        let set = self.validator_set(height);
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
        let parent = self.store.latest_block()?;
        ensure!(
            block.height == parent.height + 1,
            "expected block {}, got {}",
            parent.height + 1,
            block.height
        );
        let set = self.validator_set(block.height);
        self.verify_block(&block, &parent, &set, None)?;
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

    // ---- consensus rules ----------------------------------------------------------------

    fn is_active_validator(&self) -> Option<u64> {
        let id = self.local_id()?;
        self.validator_set(self.hs.height)
            .get(&id)
            .map(|v| v.weight)
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
        let Some(weight) = self.is_active_validator() else {
            return Ok(());
        };
        if self.hs.proposed_rounds.contains(&round) {
            return Ok(());
        }
        let identity = self.identity.as_ref().expect("active validator has keys");
        let parent = self.store.latest_block()?;
        let set = self.validator_set(height);
        let input = vrf_input(&block_randomness(&parent), height, round);
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
                let messages = self.store.pool_batch(self.config.max_block_messages)?;
                if messages.is_empty() && !self.config.allow_empty_blocks {
                    // nothing to sequence yet; try again on the next tick of this round
                    return Ok(());
                }
                let mut block = Block {
                    height,
                    round,
                    parent_hash: parent.hash(),
                    proposer: identity.id(),
                    vrf: Some(claim.clone()),
                    messages,
                    timestamp: ((self.now_ms / 1000) as u32).max(parent.timestamp),
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
        log_info(format!(
            "Proposing block {height} (round {round}, {} messages{})",
            block.messages.len(),
            valid_round.map_or(String::new(), |vr| format!(
                ", re-proposing valid round {vr}"
            ))
        ));
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
        let mut hashes = std::collections::BTreeSet::new();
        let mut votes: Vec<Vote> = self
            .hs
            .votes
            .values()
            .flat_map(|v| v.iter().filter(|vote| vote.validator == me).cloned())
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
            if let Some(polka) = self.hs.votes.get(&(VoteKind::Prevote, vr)) {
                votes.extend(
                    polka
                        .iter()
                        .filter(|v| v.block_hash == Some(hash) && v.validator != me)
                        .cloned(),
                );
            }
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
                    && self.has_quorum(VoteKind::Prevote, vr, Some(*block_hash))
                    && self
                        .hs
                        .locked
                        .is_none_or(|(lr, locked)| lr <= vr || locked == *block_hash)
            }
        }
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
            && self.store.pool_batch(1)?.is_empty();
        if best.is_none() && idle {
            // nothing anywhere to sequence: wait instead of burning rounds on nil votes
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
            let set = self.validator_set(self.hs.height);

            // commit: 2/3+ precommits for a block we know, in any round
            let commit = self.hs.votes.iter().find_map(|((kind, round), votes)| {
                if *kind != VoteKind::Precommit {
                    return None;
                }
                tally(&set, votes)
                    .into_iter()
                    .find(|(hash, w)| {
                        set.is_quorum(*w) && hash.is_some_and(|h| self.hs.blocks.contains_key(&h))
                    })
                    .map(|(hash, _)| (*round, hash.expect("checked")))
            });
            if let Some((round, hash)) = commit {
                let mut block = self.hs.blocks[&hash].clone();
                block.votes = self.hs.votes[&(VoteKind::Precommit, round)]
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
                .keys()
                .map(|(_, r)| *r)
                .filter(|r| *r > self.hs.round)
                .collect::<HashSet<_>>()
                .into_iter()
                .filter(|r| {
                    let voters: HashSet<&GenericPublicKey> =
                        [VoteKind::Prevote, VoteKind::Precommit]
                            .iter()
                            .filter_map(|k| self.hs.votes.get(&(*k, *r)))
                            .flat_map(|v| v.iter().map(|vote| &vote.validator))
                            .collect();
                    let weight: u64 = voters
                        .iter()
                        .filter_map(|id| set.get(id))
                        .map(|v| v.weight)
                        .sum();
                    (weight as u128) * 3 > set.total_weight() as u128
                })
                .max();
            if let Some(round) = skip_to {
                self.start_round(round);
                continue;
            }

            let round = self.hs.round;
            let prevotes = self
                .hs
                .votes
                .get(&(VoteKind::Prevote, round))
                .map(|v| tally(&set, v))
                .unwrap_or_default();

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
            let any_prevotes = self
                .hs
                .votes
                .get(&(VoteKind::Prevote, round))
                .map_or(0, |v| voters_weight(&set, v));
            if self.hs.step == Step::Prevote
                && self.hs.prevote_deadline.is_none()
                && set.is_quorum(any_prevotes)
            {
                self.hs.prevote_deadline = Some(self.now_ms + self.config.timing.prevote(round));
            }
            let any_precommits: u64 = self
                .hs
                .votes
                .get(&(VoteKind::Precommit, round))
                .map_or(0, |v| voters_weight(&set, v));
            if self.hs.precommit_deadline.is_none() && set.is_quorum(any_precommits) {
                self.hs.precommit_deadline =
                    Some(self.now_ms + self.config.timing.precommit(round));
            }
            return Ok(());
        }
    }

    /// Signs, persists, records and queues an own vote (at most one per kind and round).
    fn cast(&mut self, kind: VoteKind, round: u64, block_hash: Option<Hash>) -> Result<()> {
        if self.is_active_validator().is_none() || self.hs.signed.contains_key(&(kind, round)) {
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

    fn persist(&self) -> Result<()> {
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
        self.store
            .meta_put(CONSENSUS_STATE_KEY, &bincode::serialize(&state)?)
    }

    fn record_vote(&mut self, vote: Vote) -> Result<Received> {
        let known_block = vote
            .block_hash
            .is_none_or(|h| self.hs.blocks.contains_key(&h));
        let votes = self.hs.votes.entry((vote.kind, vote.round)).or_default();
        let mut equivocating = false;
        for existing in votes.iter().filter(|v| v.validator == vote.validator) {
            if existing.block_hash == vote.block_hash {
                return Ok(Received::Duplicate);
            }
            equivocating = true;
        }
        if equivocating {
            // keep conflicting votes only for values we can act on, which bounds memory:
            // known blocks are limited to one proposal per proposer and round
            ensure!(
                known_block,
                "conflicting vote for unknown block in round {}",
                vote.round
            );
            log_warn(format!(
                "validator {} equivocated ({:?}, round {})",
                hex::encode(&vote.validator[..4]),
                vote.kind,
                vote.round
            ));
        }
        votes.push(vote);
        Ok(Received::New)
    }

    fn has_quorum(&self, kind: VoteKind, round: u64, block_hash: Option<Hash>) -> bool {
        let set = self.validator_set(self.hs.height);
        self.hs
            .votes
            .get(&(kind, round))
            .and_then(|v| tally(&set, v).get(&block_hash).copied())
            .is_some_and(|w| set.is_quorum(w))
    }

    /// Checks a block's own validity (author, VRF, signature, contents); not its votes.
    fn verify_block(
        &self,
        block: &Block,
        parent: &Block,
        set: &ValidatorSet,
        now_secs: Option<u32>,
    ) -> Result<()> {
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
            block.messages.len() <= self.config.max_block_messages,
            "too many messages"
        );
        let mut ids = HashSet::new();
        for message in &block.messages {
            ensure!(
                !message.data.is_empty() && message.data.len() <= self.config.max_message_bytes,
                "invalid message size"
            );
            let id = message.id();
            ensure!(ids.insert(id), "duplicate message in block");
            ensure!(
                !self.store.is_committed(&id)?,
                "message was already sequenced"
            );
        }
        Ok(())
    }

    fn commit(&mut self, block: Block) -> Result<()> {
        let mut root = self.trie_root.clone();
        for message in &block.messages {
            let mut leaf = message_leaf(&message.data);
            root = insert_leaf(&mut self.trie, &mut leaf, TrieNode::Root(root))?;
        }
        self.store.commit_block(&block, &root)?;
        self.trie_root = root;
        self.policy.on_block_committed(&block);
        let commit_round = block.votes.first().map_or(0, |v| v.round);
        self.hs = HeightState::new(block.height + 1);
        self.start_round(0);
        self.persist()?;
        log_info(format!(
            "Committed block {} (round {commit_round}, {} messages, {} precommits), trie root {}",
            block.height,
            block.messages.len(),
            block.votes.len(),
            self.trie_root
                .hash
                .as_ref()
                .map(hex::encode)
                .unwrap_or_else(|| "empty".into())
        ));
        Ok(())
    }
}

/// Weight of distinct active validators that voted at all.
fn voters_weight(set: &ValidatorSet, votes: &[Vote]) -> u64 {
    let voters: HashSet<&GenericPublicKey> = votes.iter().map(|v| &v.validator).collect();
    voters
        .into_iter()
        .filter_map(|id| set.get(id))
        .map(|v| v.weight)
        .sum()
}

/// Weight per voted value (block hash or nil), counting only active validators.
fn tally(set: &ValidatorSet, votes: &[Vote]) -> HashMap<Option<Hash>, u64> {
    let mut weights = HashMap::new();
    for vote in votes {
        if let Some(v) = set.get(&vote.validator) {
            *weights.entry(vote.block_hash).or_insert(0) += v.weight;
        }
    }
    weights
}
