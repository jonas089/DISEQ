use ciphercurve_trie::store::types::{Hashable, Leaf};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type GenericSignature = Vec<u8>;
pub type Timestamp = u32;
pub type GenericMessageData = Vec<u8>;
pub type GenericPublicKey = Vec<u8>;
pub type Hash = [u8; 32];

pub fn sha256(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub data: GenericMessageData,
    pub timestamp: Timestamp,
}
impl Message {
    /// Canonical message id. It is the hash of the Merkle trie leaf that stores `data`,
    /// so two messages with the same payload share an id (and would collide in the trie).
    pub fn id(&self) -> Hash {
        message_id(&self.data)
    }
}

/// Hash of the trie leaf holding `data` (before its key is set).
pub fn message_id(data: &[u8]) -> Hash {
    let mut leaf = Leaf::new(Vec::new(), Some(data.to_vec()));
    leaf.hash();
    leaf.hash
        .expect("leaf hash was just computed")
        .try_into()
        .expect("trie uses 32 byte hashes")
}

/// The trie leaf for `data`, keyed by the bits of its message id.
pub fn message_leaf(data: &[u8]) -> Leaf {
    let mut leaf = Leaf::new(Vec::new(), Some(data.to_vec()));
    leaf.key = id_to_trie_key(&message_id(data));
    leaf.hash();
    leaf
}

pub fn id_to_trie_key(id: &Hash) -> Vec<u8> {
    id.iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1))
        .collect()
}

/// VRF evaluation attached to a proposal. Proves that `proposer` evaluated its VRF on the
/// round's election input; the pre-output is unique per (key, input).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VrfClaim {
    pub pre_output: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub height: u32,
    /// Round (at this height) in which the block was authored. The block may be re-proposed
    /// and committed in a later round; the commit round is the round of its votes.
    pub round: u64,
    pub parent_hash: Hash,
    /// SEC1 encoded ECDSA key of the block author (empty for genesis).
    pub proposer: GenericPublicKey,
    /// The author's VRF claim for (`height`, `round`). `None` only for genesis.
    pub vrf: Option<VrfClaim>,
    pub messages: Vec<Message>,
    pub timestamp: Timestamp,
    /// Author signature over `signing_payload(hash)`.
    pub signature: Option<GenericSignature>,
    /// Commit certificate: precommits for this block from > 2/3 of the weight, all from one
    /// round. Empty while the block is only being proposed.
    pub votes: Vec<Vote>,
}

#[derive(Serialize)]
struct BlockHeader<'a> {
    height: u32,
    round: u64,
    parent_hash: &'a Hash,
    proposer: &'a GenericPublicKey,
    vrf: &'a Option<VrfClaim>,
    messages: &'a Vec<Message>,
    timestamp: Timestamp,
}

impl Block {
    pub fn genesis(timestamp: Timestamp) -> Self {
        Block {
            height: 0,
            round: 0,
            parent_hash: [0; 32],
            proposer: Vec::new(),
            vrf: None,
            messages: Vec::new(),
            timestamp,
            signature: None,
            votes: Vec::new(),
        }
    }
    /// Hash over everything except the proposer signature and the votes.
    pub fn hash(&self) -> Hash {
        let header = BlockHeader {
            height: self.height,
            round: self.round,
            parent_hash: &self.parent_hash,
            proposer: &self.proposer,
            vrf: &self.vrf,
            messages: &self.messages,
            timestamp: self.timestamp,
        };
        sha256(&[&bincode::serialize(&header).expect("header serializes")])
    }
    pub fn signing_payload(hash: &Hash) -> Vec<u8> {
        [b"DISEQ_BLOCK_V1".as_slice(), hash].concat()
    }
}

/// A proposal of `block` for (`height`, `round`). `proposer` won (or took part in) the VRF
/// election of this round; it may differ from the block author when a block that already
/// gathered a 2/3+ prevote quorum in `valid_round` is re-proposed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub height: u32,
    pub round: u64,
    pub valid_round: Option<u64>,
    pub block: Block,
    pub proposer: GenericPublicKey,
    pub vrf: VrfClaim,
    pub signature: GenericSignature,
}
impl Proposal {
    pub fn signing_payload(
        height: u32,
        round: u64,
        valid_round: Option<u64>,
        block_hash: &Hash,
    ) -> Vec<u8> {
        [
            b"DISEQ_PROPOSAL_V1".as_slice(),
            &height.to_be_bytes(),
            &round.to_be_bytes(),
            &valid_round.map_or([0xff; 9], |r| {
                let mut b = [0u8; 9];
                b[1..].copy_from_slice(&r.to_be_bytes());
                b
            }),
            block_hash,
        ]
        .concat()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VoteKind {
    Prevote,
    Precommit,
}

/// A prevote or precommit for `block_hash` (or nil) at (`height`, `round`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    pub kind: VoteKind,
    pub height: u32,
    pub round: u64,
    pub block_hash: Option<Hash>,
    pub validator: GenericPublicKey,
    pub signature: GenericSignature,
}
impl Vote {
    pub fn signing_payload(
        kind: VoteKind,
        height: u32,
        round: u64,
        block_hash: &Option<Hash>,
    ) -> Vec<u8> {
        [
            b"DISEQ_VOTE_V2".as_slice(),
            &[kind as u8],
            &height.to_be_bytes(),
            &round.to_be_bytes(),
            &block_hash.map_or([0u8; 33], |h| {
                let mut b = [1u8; 33];
                b[1..].copy_from_slice(&h);
                b
            }),
        ]
        .concat()
    }
}
