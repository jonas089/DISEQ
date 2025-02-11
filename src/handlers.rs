use crate::config::consensus::CONSENSUS_THRESHOLD;
use crate::config::network::PEERS;
use crate::gossipper::Gossipper;
use crate::state::server::BlockStore;
use crate::state::server::InMemoryConsensus;
use crate::state::server::SqLiteBlockStore;
use crate::types::BlockCommitment;
use crate::types::GenericSignature;
use crate::{crypto::ecdsa::deserialize_vk, types::Block};
use crate::{get_current_time, ServerState};
use colored::Colorize;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::Signature;
use patricia_trie::{
    insert_leaf,
    store::types::{Hashable, Leaf, Node},
};
use reqwest::Response;

pub async fn handle_synchronization_response(
    shared_state_lock: &mut tokio::sync::MutexGuard<'_, ServerState>,
    block_state_lock: &mut tokio::sync::MutexGuard<'_, BlockStore>,
    consensus_state_lock: &mut tokio::sync::MutexGuard<'_, InMemoryConsensus>,
    response: Response,
    next_height: u32,
) {
    println!("[Info] Querying Block: {}", &next_height);
    let block_serialized = response.text().await.unwrap();
    if block_serialized != "[Warning] Requested Block that does not exist" {
        let block: Block = serde_json::from_str(&block_serialized).unwrap();
        block_state_lock.insert_block(next_height, block.clone());
        // insert transactions into the trie
        let mut root_node = Node::Root(shared_state_lock.merkle_trie_root.clone());
        let transactions = &block.transactions;
        for transaction in transactions {
            let mut leaf = Leaf::new(Vec::new(), Some(transaction.data.clone()));
            leaf.hash();
            leaf.key = leaf
                .hash
                .clone()
                .unwrap()
                .iter()
                .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1))
                .collect();
            leaf.hash();
            let new_root = insert_leaf(
                &mut shared_state_lock.merkle_trie_state,
                &mut leaf,
                root_node,
            )
            .expect("[Critical] Failed to insert leaf!");
            root_node = Node::Root(new_root);
        }
        // update trie root
        shared_state_lock.merkle_trie_root = root_node
            .unwrap_as_root()
            .expect("[Critical] Failed to unwrap as root, this should never happen :(");
        consensus_state_lock.reinitialize();
        println!(
            "{}",
            format_args!("{} Synchronized Block: {}", "[Info]".green(), next_height)
        );
        println!(
            "{}",
            format_args!(
                "{} New Trie Root: {:?}",
                "[Info]".green(),
                shared_state_lock.merkle_trie_root.hash
            )
        );
    }
}

pub async fn handle_block_proposal(
    shared_state_lock: &mut tokio::sync::MutexGuard<'_, ServerState>,
    block_state_lock: &mut tokio::sync::MutexGuard<'_, BlockStore>,
    consensus_state_lock: &mut tokio::sync::MutexGuard<'_, InMemoryConsensus>,
    proposal: &mut Block,
    error_response: String,
) -> Option<String> {
    println!("[Info] Handling Block proposal!");
    // will refuse this block if previously signed a lower block
    // -> 'lowest' block always wins, both in consensus and synchronization
    // this is the way this sequencer deals with chain splits
    let early_revert: bool = match &consensus_state_lock.lowest_block {
        Some(v) => {
            if proposal.to_bytes() < v.clone() {
                consensus_state_lock.lowest_block = Some(proposal.to_bytes());
                false
            } else if proposal.to_bytes() == v.clone() {
                false
            } else {
                true
            }
        }
        None => {
            consensus_state_lock.lowest_block = Some(proposal.to_bytes());
            false
        }
    };
    if early_revert {
        println!("[Warning] Block rejected, lower block known!");
        return Some(error_response);
    }
    // sign the block if it has not been signed yet
    let mut is_signed = false;
    let block_commitments = proposal.commitments.clone().unwrap_or(Vec::new());
    let mut commitment_count: u32 = 0;
    for commitment in block_commitments {
        let commitment_vk = deserialize_vk(&commitment.validator);
        if consensus_state_lock.validators.contains(&commitment_vk) {
            match commitment_vk.verify(
                &proposal.to_bytes(),
                &Signature::from_slice(&commitment.signature).unwrap(),
            ) {
                Ok(_) => commitment_count += 1,
                Err(_) => {
                    println!(
                        "{}",
                        format_args!("{} Invalid Commitment was Ignored", "[Warning]".yellow())
                    )
                }
            }
        } else {
            println!(
                "{}",
                format_args!("{} Invalid Proposal found with invalid VK", "[Error]".red())
            );
        }
        if commitment.validator
            == consensus_state_lock
                .local_validator
                .to_sec1_bytes()
                .to_vec()
        {
            is_signed = true;
        }
    }
    println!(
        "[Info] Commitment count for proposal: {}",
        &commitment_count
    );
    let previous_block_height = block_state_lock.current_block_height() - 1;
    if proposal.height != previous_block_height + 1 {
        return Some(error_response);
    }
    if commitment_count >= CONSENSUS_THRESHOLD {
        println!(
            "{}",
            format_args!("{} Received Valid Block", "[Info]".green())
        );
        block_state_lock.insert_block(proposal.height, proposal.clone());
        // insert transactions into the trie
        let mut root_node = Node::Root(shared_state_lock.merkle_trie_root.clone());
        for transaction in &proposal.transactions {
            let mut leaf = Leaf::new(Vec::new(), Some(transaction.data.clone()));
            leaf.hash();
            leaf.key = leaf
                .hash
                .clone()
                .unwrap()
                .iter()
                .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1))
                .collect();
            leaf.hash();
            // currently duplicate insertion will kill sequencer runtime
            let new_root = insert_leaf(
                &mut shared_state_lock.merkle_trie_state,
                &mut leaf,
                root_node,
            ).expect("Failed to insert, did someone try to insert a duplicate? - In production this should not kill runtime, but currently it does - hihi!");
            root_node = Node::Root(new_root);
        }
        // update in-memory trie root
        shared_state_lock.merkle_trie_root = root_node
            .unwrap_as_root()
            .expect("failed to unwrap as root, this should never happen :(");
        println!(
            "{}",
            format_args!("{} Block was stored: {}", "[Info]".green(), proposal.height)
        );
        println!(
            "{}",
            format_args!(
                "{} New Trie Root: {:?}",
                "[Info]".green(),
                shared_state_lock.merkle_trie_root.hash
            )
        );
    } else if !is_signed && (previous_block_height + 1 == proposal.height) {
        let local_sk = consensus_state_lock.local_signing_key.clone();
        let block_bytes = proposal.to_bytes();
        let signature: Signature = local_sk.sign(&block_bytes);
        let signature_serialized: GenericSignature = signature.to_bytes().to_vec();
        let unix_timestamp = get_current_time();
        let commitment = BlockCommitment {
            signature: signature_serialized,
            validator: consensus_state_lock
                .local_validator
                .to_sec1_bytes()
                .to_vec()
                .clone(),
            timestamp: unix_timestamp,
        };
        match proposal.commitments.as_mut() {
            Some(commitments) => commitments.push(commitment),
            None => proposal.commitments = Some(vec![commitment]),
        }
        println!("[Info] Signed Block is being gossipped");
        let last_block_unix_timestamp = block_state_lock
            .get_block_by_height(previous_block_height)
            .timestamp;

        // todo: spawn a task for this
        let gossipper = Gossipper {
            peers: PEERS.to_vec(),
            client: reqwest::Client::new(),
        };

        let proposal = proposal.clone();
        tokio::spawn(async move {
            let _ = gossipper
                .gossip_pending_block(proposal, last_block_unix_timestamp)
                .await;
        });
    } else {
        println!(
            "{}",
            format_args!(
                "{} Block is signed but lacks commitments",
                "[Warning]".yellow()
            )
        );
    }
    None
}
