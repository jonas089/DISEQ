//! Everything that is signed, hashed or sent between validators.
//!
//! Each signed object has a `signing_payload` with its own domain tag, so a signature for one
//! kind of object can never be replayed as another.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type GenericSignature = Vec<u8>;
pub type Timestamp = u32;
pub type GenericPublicKey = Vec<u8>;
pub type Hash = [u8; 32];

pub fn sha256(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// A client message. Consensus never looks inside `data`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub data: Vec<u8>,
    pub timestamp: Timestamp,
}
impl Message {
    /// Canonical id: two messages with the same payload are the same message and are
    /// sequenced at most once.
    pub fn id(&self) -> Hash {
        sha256(&[b"DISEQ_MESSAGE_V1", &self.data])
    }
}

// ---- data plane: batches and their availability certificates -------------------------------

/// Messages a validator collected from its clients, broadcast to all validators.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub author: GenericPublicKey,
    /// Per-author counter; only makes digests of equal contents unique.
    pub seq: u64,
    pub messages: Vec<Message>,
    /// Author signature over `Batch::signing_payload(digest)`.
    pub signature: GenericSignature,
}
impl Batch {
    /// Hash over author, seq and messages (not the signature).
    pub fn digest(&self) -> Hash {
        #[derive(Serialize)]
        struct Content<'a>(&'a GenericPublicKey, u64, &'a Vec<Message>);
        let content = bincode::serialize(&Content(&self.author, self.seq, &self.messages))
            .expect("batch serializes");
        sha256(&[b"DISEQ_BATCH_V1", &content])
    }
    pub fn signing_payload(digest: &Hash) -> Vec<u8> {
        [b"DISEQ_BATCH_SIG_V1".as_slice(), digest].concat()
    }
}

/// "I validated and stored the batch `digest` with `messages` messages, and will serve it."
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub digest: Hash,
    pub messages: u32,
    pub validator: GenericPublicKey,
    pub signature: GenericSignature,
}
impl Attestation {
    pub fn signing_payload(digest: &Hash, messages: u32) -> Vec<u8> {
        [
            b"DISEQ_ATTESTATION_V1".as_slice(),
            digest,
            &messages.to_be_bytes(),
        ]
        .concat()
    }
}

/// Proof of availability: attestations for one batch from more than 2/3 of the weight. At
/// least one honest validator among them stores the batch, so anyone can fetch it later.
/// Blocks order certificates, never raw messages.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BatchCert {
    pub digest: Hash,
    pub author: GenericPublicKey,
    pub messages: u32,
    /// (validator, signature over `Attestation::signing_payload(digest, messages)`)
    pub attestations: Vec<(GenericPublicKey, GenericSignature)>,
}
impl BatchCert {
    /// Identifies this exact certificate (digest and signatures), for verification caching.
    pub fn hash(&self) -> Hash {
        sha256(&[&bincode::serialize(self).expect("certificate serializes")])
    }
}

// ---- consensus: blocks, proposals, votes -----------------------------------------------------

/// VRF evaluation attached to a proposal. Proves that `proposer` evaluated its VRF on the
/// round's election input; the pre-output is unique per (key, input).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VrfClaim {
    pub pre_output: Vec<u8>,
    pub proof: Vec<u8>,
}

/// A block orders batches: its message sequence is the concatenation of its batches'
/// messages, minus messages that were already sequenced (see the node's sequencer).
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
    pub batches: Vec<BatchCert>,
    pub timestamp: Timestamp,
    /// Author signature over `signing_payload(hash)`.
    pub signature: Option<GenericSignature>,
    /// Commit certificate: precommits for this block from > 2/3 of the weight, all from one
    /// round. Empty while the block is only being proposed.
    pub votes: Vec<Vote>,
}

impl Block {
    pub fn genesis(timestamp: Timestamp) -> Self {
        Block {
            height: 0,
            round: 0,
            parent_hash: [0; 32],
            proposer: Vec::new(),
            vrf: None,
            batches: Vec::new(),
            timestamp,
            signature: None,
            votes: Vec::new(),
        }
    }
    /// Hash over everything except the author signature and the votes.
    pub fn hash(&self) -> Hash {
        #[derive(Serialize)]
        struct Header<'a> {
            height: u32,
            round: u64,
            parent_hash: &'a Hash,
            proposer: &'a GenericPublicKey,
            vrf: &'a Option<VrfClaim>,
            batches: &'a Vec<BatchCert>,
            timestamp: Timestamp,
        }
        let header = Header {
            height: self.height,
            round: self.round,
            parent_hash: &self.parent_hash,
            proposer: &self.proposer,
            vrf: &self.vrf,
            batches: &self.batches,
            timestamp: self.timestamp,
        };
        sha256(&[
            b"DISEQ_BLOCK_V2",
            &bincode::serialize(&header).expect("header serializes"),
        ])
    }
    pub fn signing_payload(hash: &Hash) -> Vec<u8> {
        [b"DISEQ_BLOCK_V2".as_slice(), hash].concat()
    }
    /// Number of messages in the block's batches (before deduplication).
    pub fn message_count(&self) -> u64 {
        self.batches.iter().map(|b| b.messages as u64).sum()
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
