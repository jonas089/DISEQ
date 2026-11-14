//! # diseq-consensus
//!
//! The protocol core of DISEQ, free of I/O: no networking, no threads, no database. Every
//! input is a method call, every output a return value, so the whole protocol can be read,
//! tested and simulated deterministically.
//!
//! DISEQ agrees on an order of **certified batches** of messages:
//!
//! ```text
//!  clients ──► validator ──batch──► all validators ──attestation──► author
//!                                                                    │ > 2/3 attestations
//!                                                                    ▼
//!                       Tendermint block ◄── proposer ◄── BatchCert (proof of availability)
//! ```
//!
//! | Concern                                   | Module            |
//! |-------------------------------------------|-------------------|
//! | Messages, batches, blocks, votes (wire)   | [`types`]         |
//! | Batch validity, attestations, certificates| [`availability`]  |
//! | Proposer election (VRF)                   | [`election`]      |
//! | Validator sets, quorum (> 2/3), epochs    | [`validators`]    |
//! | Consensus state machine, locks, commits   | [`tendermint`]    |
//! | Vote storage, equivocation, tallies       | [`votes`]         |
//! | Round timeouts                            | [`timeouts`]      |
//! | Storage interface                         | [`store`]         |
//! | Signatures and VRF                        | [`crypto`]        |
//!
//! Fault model: safety and liveness hold while faulty validators hold less than 1/3 of the
//! weight; liveness additionally needs the network to eventually deliver messages in time.
pub mod availability;
pub mod config;
pub mod crypto;
pub mod election;
pub mod fixtures;
pub mod store;
pub mod tendermint;
pub mod timeouts;
pub mod types;
pub mod validators;
pub mod votes;

pub use config::ConsensusConfig;
pub use crypto::LocalValidator;
pub use store::{ConsensusStore, MemStore};
pub use tendermint::{Consensus, Outgoing};
pub use votes::Received;

pub(crate) fn log_info(msg: impl std::fmt::Display) {
    println!("[Info] {msg}");
}
pub(crate) fn log_warn(msg: impl std::fmt::Display) {
    println!("[Warning] {msg}");
}
