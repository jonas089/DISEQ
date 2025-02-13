mod api;
mod config;
mod consensus;
mod crypto;
mod gossipper;
mod handlers;
mod state;
mod types;
use api::{
    commit, get_block, get_commitments, get_height, get_pool, get_state_root_hash, merkle_proof,
    propose, schedule,
};
use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Extension, Router,
};
use colored::*;
use config::{
    consensus::{CLEARING_PHASE, ROUND_DURATION},
    network::PEERS,
};
use consensus::logic::{current_round, evaluate_commitment, get_committing_validator};
use gossipper::send_proposal;
use k256::ecdsa::{signature::SignerMut, Signature};
use l2_sequencer::initial_print;
use prover::generate_random_number;
use reqwest::Client;
use state::server::{BlockStore, InMemoryConsensus, TransactionPool};
use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use types::{Block, ConsensusCommitment};
#[allow(unused)]
use {
    gossipper::{docker_skip_self, Gossipper},
    handlers::handle_synchronization_response,
    reqwest::Response,
};
use {
    patricia_trie::store::{db::sql::TrieDB as MerkleTrieDB, types::Root},
    state::server::{SqLiteBlockStore, SqLiteTransactionPool},
};

struct ServerState {
    merkle_trie_state: MerkleTrieDB,
    merkle_trie_root: Root,
    local_gossipper: Gossipper,
}

// currently only supports mock net
#[allow(unused)]
async fn synchronization_loop(
    shared_state: Arc<Mutex<ServerState>>,
    shared_block_state: Arc<Mutex<BlockStore>>,
    shared_pool_state: Arc<Mutex<TransactionPool>>,
    shared_consensus_state: Arc<Mutex<InMemoryConsensus>>,
) {
    // only sync when no prioritized task is running (api, consensus) - falling behind is ok for now
    {
        let mut block_state_lock = shared_block_state.lock().await;
        let next_height = block_state_lock.current_block_height();
        drop(block_state_lock);
        let gossipper = Gossipper {
            peers: PEERS.to_vec(),
            client: Client::new(),
        };

        for peer in gossipper.peers {
            // todo: make this generic for n amount of nodes
            let this_node = env::var("API_HOST_WITH_PORT").unwrap_or("0.0.0.0:8080".to_string());
            if docker_skip_self(&this_node, &peer) {
                continue;
            }
            let response: Option<Response> = match gossipper
                .client
                .get(format!("http://{}{}{}", &peer, "/get/block/", next_height))
                //.timeout(Duration::from_secs(20))
                .send()
                .await
            {
                Ok(response) => Some(response),
                Err(_) => None,
            };
            match response {
                Some(response) => {
                    handle_synchronization_response(
                        shared_state.clone(),
                        shared_block_state.clone(),
                        shared_consensus_state.clone(),
                        response,
                        next_height,
                    )
                    .await;
                }
                _ => {}
            }
        }
    }
    #[cfg(not(feature = "local-net"))]
    {
        todo!("Implement mainnet synchronization!");
    }
}
async fn consensus_loop(
    shared_state: Arc<Mutex<ServerState>>,
    shared_block_state: Arc<Mutex<BlockStore>>,
    shared_pool_state: Arc<Mutex<TransactionPool>>,
    shared_consensus_state: Arc<Mutex<InMemoryConsensus>>,
) {
    let unix_timestamp = get_current_time();
    let (block_state_lock, pool_state_lock) =
        tokio::join!(shared_block_state.lock(), shared_pool_state.lock());
    let mut consensus_state_lock = shared_consensus_state.lock().await;
    let last_block_unix_timestamp = block_state_lock
        .get_block_by_height(block_state_lock.current_block_height() - 1)
        .timestamp;

    let rounds_since = (unix_timestamp - last_block_unix_timestamp) / ROUND_DURATION;
    if unix_timestamp >= last_block_unix_timestamp + rounds_since * ROUND_DURATION
        && unix_timestamp
            <= last_block_unix_timestamp + rounds_since * ROUND_DURATION + CLEARING_PHASE
    {
        println!(
            "[Info]: Reinitializing consensus state, clearing phase remaining: {}",
            (last_block_unix_timestamp + ROUND_DURATION - unix_timestamp)
        );
        consensus_state_lock.reinitialize();
        return;
    }

    let committing_validator = get_committing_validator(
        last_block_unix_timestamp,
        consensus_state_lock.validators.clone(),
    );

    println!(
        "[Info] Current round: {}",
        current_round(last_block_unix_timestamp)
    );

    let previous_block_height = block_state_lock.current_block_height() - 1;
    if consensus_state_lock.local_validator == committing_validator
        && !consensus_state_lock.committed
    {
        let random_zk_number = generate_random_number(
            consensus_state_lock
                .local_validator
                .to_sec1_bytes()
                .to_vec(),
            (previous_block_height + 1).to_be_bytes().to_vec(),
        );
        let commitment = ConsensusCommitment {
            validator: consensus_state_lock
                .local_validator
                .to_sec1_bytes()
                .to_vec(),
            receipt: random_zk_number,
        };
        let local_gossipper = {
            let shared_state_lock = shared_state.try_lock();
            if let Ok(state) = shared_state_lock {
                state.local_gossipper.clone()
            } else {
                return;
            }
        };
        let _ = local_gossipper
            .gossip_consensus_commitment(commitment.clone())
            .await;

        let proposing_validator =
            evaluate_commitment(commitment, consensus_state_lock.validators.clone());
        consensus_state_lock.round_winner = Some(proposing_validator);
        consensus_state_lock.committed = true;
    }

    if consensus_state_lock.round_winner.is_none() {
        return;
    }

    let proposing_validator = consensus_state_lock.round_winner.unwrap();
    let transactions = pool_state_lock.get_all_transactions();

    if consensus_state_lock.local_validator == proposing_validator && !consensus_state_lock.proposed
    {
        let mut proposed_block = Block {
            height: previous_block_height + 1,
            signature: None,
            transactions,
            commitments: None,
            timestamp: unix_timestamp,
        };
        let mut signing_key = consensus_state_lock.local_signing_key.clone();
        let signature: Signature = signing_key.sign(&proposed_block.to_bytes());
        proposed_block.signature = Some(signature.to_bytes().to_vec());
        println!("{}", format_args!("{} Proposing Block!", "[Info]".green()));
        // only for testing, send proposal to one node that is not self
        let this_node =
            env::var("API_HOST_WITH_PORT").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        // submit to a peer that is not self (single peer for testing) - the peer should
        // further gossip this proposal until it gains enough attestations
        let trusted_peer: &'static str = PEERS
            .iter()
            .find(|&&ref peer| peer != &this_node)
            .cloned()
            .expect("[Error] No valid peer found!");
        drop(block_state_lock);
        drop(pool_state_lock);
        drop(consensus_state_lock);
        let _ = send_proposal(
            reqwest::Client::new(),
            trusted_peer,
            serde_json::to_string(&proposed_block).unwrap(),
        )
        .await;

        let maybe_pool_lock = shared_pool_state.try_lock();
        let mut pool_state_lock = maybe_pool_lock.expect("Failed to unwrap pool lock");
        let maybe_consensus_lock = shared_consensus_state.try_lock();
        let mut consensus_state_lock = maybe_consensus_lock.expect("Failed to get consensus lock");
        consensus_state_lock.proposed = true;
        pool_state_lock.reinitialize()
    }
}
#[tokio::main]
async fn main() {
    initial_print();
    let mut block_state = {
        let block_state: BlockStore = BlockStore {
            db_path: env::var("PATH_TO_DB").unwrap_or("database.sqlite".to_string()),
        };
        block_state.setup();
        block_state
    };
    block_state.trigger_genesis(get_current_time());
    let pool_state: TransactionPool = {
        let pool_state: TransactionPool = TransactionPool {
            size: 0,
            db_path: env::var("PATH_TO_DB").unwrap_or("database.sqlite".to_string()),
        };
        pool_state.setup();
        pool_state
    };
    let consensus_state: InMemoryConsensus = InMemoryConsensus::empty_with_default_validators();
    let merkle_trie_state: MerkleTrieDB = MerkleTrieDB {
        path: env::var("PATH_TO_DB").unwrap_or("database.sqlite".to_string()),
        cache: None,
    };
    merkle_trie_state.setup();
    let merkle_trie_root: Root = Root::empty();
    let local_gossipper: Gossipper = Gossipper {
        peers: PEERS.to_vec(),
        client: Client::new(),
    };
    let shared_state: Arc<Mutex<ServerState>> = Arc::new(Mutex::new(ServerState {
        merkle_trie_state,
        merkle_trie_root,
        local_gossipper,
    }));

    let shared_block_state: Arc<Mutex<BlockStore>> = Arc::new(Mutex::new(block_state));
    let shared_pool_state: Arc<Mutex<TransactionPool>> = Arc::new(Mutex::new(pool_state));
    let shared_consensus_state: Arc<Mutex<InMemoryConsensus>> =
        Arc::new(Mutex::new(consensus_state));

    let host_with_port = env::var("API_HOST_WITH_PORT").unwrap_or("0.0.0.0:8080".to_string());
    let formatted_msg = format!(
        "{}{}",
        "Starting Node: ".green().italic(),
        &host_with_port.yellow().bold()
    );
    println!("{}", formatted_msg);

    let synchronization_task = tokio::spawn({
        let shared_state = Arc::clone(&shared_state);
        let shared_block_state = Arc::clone(&shared_block_state);
        let shared_pool_state = Arc::clone(&shared_pool_state);
        let shared_consensus_state = Arc::clone(&shared_consensus_state);
        async move {
            loop {
                // for now the loop syncs one block at a time, this can be optimized
                synchronization_loop(
                    Arc::clone(&shared_state),
                    Arc::clone(&shared_block_state),
                    Arc::clone(&shared_pool_state),
                    Arc::clone(&shared_consensus_state),
                )
                .await;
                tokio::time::sleep(Duration::from_secs(120)).await;
            }
        }
    });
    let consensus_task = tokio::spawn({
        let shared_state = Arc::clone(&shared_state);
        let shared_block_state = Arc::clone(&shared_block_state);
        let shared_pool_state = Arc::clone(&shared_pool_state);
        let shared_consensus_state = Arc::clone(&shared_consensus_state);
        async move {
            loop {
                consensus_loop(
                    Arc::clone(&shared_state),
                    Arc::clone(&shared_block_state),
                    Arc::clone(&shared_pool_state),
                    Arc::clone(&shared_consensus_state),
                )
                .await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    });
    let api_task = tokio::spawn({
        let shared_state = Arc::clone(&shared_state);
        let shared_block_state = Arc::clone(&shared_block_state);
        let shared_pool_state = Arc::clone(&shared_pool_state);
        let shared_consensus_state = Arc::clone(&shared_consensus_state);
        async move {
            let api = Router::new()
                .route("/get/pool", get(get_pool))
                .route("/get/commitments", get(get_commitments))
                .route("/get/block/:height", get(get_block))
                .route("/get/height", get(get_height))
                .route("/get/state_root_hash", get(get_state_root_hash))
                .route("/schedule", post(schedule))
                .route("/commit", post(commit))
                .route("/propose", post(propose))
                .route("/merkle_proof", post(merkle_proof))
                .layer(DefaultBodyLimit::max(10000000))
                .layer(Extension(shared_state))
                .layer(Extension(shared_block_state))
                .layer(Extension(shared_pool_state))
                .layer(Extension(shared_consensus_state));

            let listener = tokio::net::TcpListener::bind(&host_with_port)
                .await
                .unwrap();
            axum::serve(listener, api).await.unwrap();
        }
    });
    tokio::select! {
        sync_task_res = synchronization_task => {
            match sync_task_res {
                Ok(_) => println!("{}", format_args!("{} Synchronization task concluded without error", "[Warning]".yellow())),
                Err(e) => println!("{}", format_args!("{} Synchronization task failed with error: {}", "[Error]".red(), e))
            }
        },
        consensus_task_res = consensus_task => {
            match consensus_task_res {
                Ok(_) => println!("{}", format_args!("{} Consensus task concluded without error", "[Warning]".yellow())),
                Err(e) => println!("{}", format_args!("{} Consensus task failed with error: {}", "[Error]".red(), e))
            }
        },
        api_task_res = api_task => {
            match api_task_res{
                Ok(_) => println!("{}", format_args!("{} API task concluded without error", "[Warning]".yellow())),
                Err(e) => println!("{}", format_args!("{} API task failed with error: {}", "[Error]".red(), e))
            }
        }
    }
}
pub fn get_current_time() -> u32 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs() as u32
}
