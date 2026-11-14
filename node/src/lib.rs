//! # diseq-node
//!
//! Everything around the protocol core ([`diseq_consensus`]) that does I/O.
//!
//! | Concern                                             | Module                    |
//! |-----------------------------------------------------|---------------------------|
//! | Single writer, startup, message routing             | [`runtime`]               |
//! | Batching client messages, attestations, retries     | [`dissemination`]         |
//! | Committed blocks → final message sequence (dedup)   | [`sequencer`]             |
//! | Wire messages between nodes                         | [`network`]               |
//! | Per-peer batched HTTP transport                     | [`network::transport`]    |
//! | Peer routes (`/p2p/*`)                              | [`network::peer_api`]     |
//! | Block sync, batch fetching                          | [`network::sync`]         |
//! | Client routes                                       | [`api`]                   |
//! | RocksDB: chain, batches, sequence, Merkle trie      | [`storage`]               |
//! | Configuration                                       | [`config`]                |
use colored::Colorize;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub mod api;
pub mod config;
pub mod dissemination;
pub mod network;
pub mod runtime;
pub mod sequencer;
pub mod storage;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

pub fn log_info(msg: impl std::fmt::Display) {
    println!("{} {}", "[Info]".green(), msg);
}
pub fn log_warn(msg: impl std::fmt::Display) {
    println!("{} {}", "[Warning]".yellow(), msg);
}

pub fn initial_print() {
    use viuer::{print_from_file, Config};
    print!("\x1b[2J\x1b[H");
    let _ = std::io::stdout().flush();
    let config = Config {
        width: Some(60),
        height: None,
        ..Default::default()
    };
    // the logo is cosmetic, never fail startup over it
    let _ = print_from_file("./resources/DISEQ/icon-bg.jpg", &config);
    println!(
        "\n {} \n",
        "| WELCOME TO DISEQ - your open source, general purpose, message sequencer |"
            .bold()
            .italic()
            .blue()
    );
}
