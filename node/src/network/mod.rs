//! Node-to-node networking: bincode over HTTP.
//!
//! Two streams per peer, each a bounded queue drained in batches ([`transport`]):
//!
//! * **consensus** (`POST /p2p/consensus`, [`PeerMsg`]): proposals, votes, attestations and
//!   batch certificates. Small and latency critical; always handled first.
//! * **data** (`POST /p2p/data`, [`DataMsg`]): batches, and client messages a full node
//!   forwards to validators. Bulk traffic.
//!
//! Pull requests (block sync and batch fetching) are plain request/response calls
//! ([`sync`]). Routes are served by [`peer_api`].
pub mod peer_api;
pub mod peers;
pub mod sync;
pub mod transport;
pub mod wire;

use diseq_consensus::types::{Attestation, Batch, BatchCert, Message, Proposal, Vote};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum PeerMsg {
    Proposal(Proposal),
    Vote(Vote),
    /// Sent only to the batch's author.
    Attestation(Attestation),
    Cert(BatchCert),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DataMsg {
    Batch(Batch),
    /// Client messages forwarded by a non-validator.
    Messages(Vec<Message>),
}
