use crate::get_current_time_ms;
use crate::gossipper::Gossipper;
use crate::node::{Node, Outgoing, Received};
use crate::types::{Hash, Message, Proposal, Vote};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Maximum number of messages returned by one `/get/pool/messages` request.
pub const POOL_FETCH_LIMIT: usize = 1_000;

#[derive(Clone)]
pub struct AppState {
    pub node: Arc<Mutex<Node>>,
    pub gossip: Gossipper,
}

type ApiResult<T> = Result<T, (StatusCode, String)>;

fn bad_request(e: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, format!("[Error] {e:#}"))
}
fn internal(e: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("[Error] {e:#}"))
}

pub fn router(state: AppState) -> Router {
    Router::new()
        // clients
        .route("/schedule", post(schedule))
        .route("/merkle_proof", post(merkle_proof))
        .route("/get/block/:height", get(get_block))
        .route("/get/height", get(get_height))
        .route("/get/state_root_hash", get(get_state_root_hash))
        .route("/get/validators", get(get_validators))
        .route("/get/pool", get(get_pool))
        // peers
        .route("/gossip/message", post(gossip_message))
        .route("/propose", post(propose))
        .route("/vote", post(vote))
        .route("/get/pool/ids", get(get_pool_ids))
        .route("/get/pool/messages", post(get_pool_messages))
        .layer(DefaultBodyLimit::max(10_000_000))
        .with_state(state)
}

async fn accept_message(state: &AppState, message: &Message) -> ApiResult<Received> {
    let (received, peers) = {
        let mut node = state.node.lock().await;
        let received = node.submit_message(message).map_err(bad_request)?;
        (received, node.peers().map_err(internal)?)
    };
    if received == Received::New {
        state.gossip.broadcast(peers, "/gossip/message", message);
    }
    Ok(received)
}

/// Client entry point: adds the message to the local mempool and gossips it to all peers, so
/// whichever validator wins the next election can include it.
async fn schedule(
    State(state): State<AppState>,
    Json(message): Json<Message>,
) -> ApiResult<String> {
    match accept_message(&state, &message).await? {
        Received::New => Ok(format!("[Ok] Message is being sequenced: {:?}", message)),
        Received::Duplicate => Ok(format!("[Ok] Message already known: {:?}", message)),
    }
}

async fn gossip_message(
    State(state): State<AppState>,
    Json(message): Json<Message>,
) -> ApiResult<&'static str> {
    accept_message(&state, &message).await?;
    Ok("[Ok]")
}

/// Broadcasts what the node produced in reaction to an input (e.g. its own precommit).
pub fn broadcast_outgoing(gossip: &Gossipper, peers: &[String], outgoing: Vec<Outgoing>) {
    for item in outgoing {
        match item {
            Outgoing::Proposal(p) => gossip.broadcast(peers.to_vec(), "/propose", &p),
            Outgoing::Vote(v) => gossip.broadcast(peers.to_vec(), "/vote", &v),
        }
    }
}

async fn propose(
    State(state): State<AppState>,
    Json(proposal): Json<Proposal>,
) -> ApiResult<&'static str> {
    let ((received, outgoing), peers) = {
        let mut node = state.node.lock().await;
        let result = node
            .on_proposal(proposal.clone(), get_current_time_ms())
            .map_err(bad_request)?;
        (result, node.peers().map_err(internal)?)
    };
    if received == Received::New {
        state.gossip.broadcast(peers.clone(), "/propose", &proposal);
    }
    broadcast_outgoing(&state.gossip, &peers, outgoing);
    Ok("[Ok] Proposal was processed")
}

async fn vote(State(state): State<AppState>, Json(vote): Json<Vote>) -> ApiResult<&'static str> {
    let ((received, outgoing), peers) = {
        let mut node = state.node.lock().await;
        let result = node
            .on_vote(vote.clone(), get_current_time_ms())
            .map_err(bad_request)?;
        (result, node.peers().map_err(internal)?)
    };
    if received == Received::New {
        state.gossip.broadcast(peers.clone(), "/vote", &vote);
    }
    broadcast_outgoing(&state.gossip, &peers, outgoing);
    Ok("[Ok] Vote was processed")
}

async fn merkle_proof(
    State(state): State<AppState>,
    Json(key): Json<Vec<u8>>,
) -> ApiResult<String> {
    let mut node = state.node.lock().await;
    let proof = node.merkle_proof(key).map_err(bad_request)?;
    serde_json::to_string(&proof).map_err(|e| internal(e.into()))
}

async fn get_block(State(state): State<AppState>, Path(height): Path<u32>) -> ApiResult<String> {
    let node = state.node.lock().await;
    match node.store.block(height).map_err(internal)? {
        Some(block) => serde_json::to_string(&block).map_err(|e| internal(e.into())),
        None => Ok("[Warning] Requested Block that does not exist".to_string()),
    }
}

async fn get_height(State(state): State<AppState>) -> ApiResult<Json<u32>> {
    let node = state.node.lock().await;
    Ok(Json(node.store.latest_height().map_err(internal)?))
}

async fn get_state_root_hash(State(state): State<AppState>) -> ApiResult<String> {
    let node = state.node.lock().await;
    serde_json::to_string(node.trie_root()).map_err(|e| internal(e.into()))
}

#[derive(Serialize)]
struct ValidatorInfo {
    id: String,
    vrf_key: String,
    weight: u64,
    address: String,
}

async fn get_validators(State(state): State<AppState>) -> ApiResult<Json<Vec<ValidatorInfo>>> {
    let node = state.node.lock().await;
    let (height, _, _) = node.consensus_position();
    Ok(Json(
        node.validator_set(height)
            .iter()
            .map(|v| ValidatorInfo {
                id: hex::encode(v.id_bytes()),
                vrf_key: hex::encode(&v.vrf_key),
                weight: v.weight,
                address: v.address.clone(),
            })
            .collect(),
    ))
}

async fn get_pool(State(state): State<AppState>) -> ApiResult<Json<Vec<Message>>> {
    let node = state.node.lock().await;
    Ok(Json(
        node.store.pool_batch(POOL_FETCH_LIMIT).map_err(internal)?,
    ))
}

async fn get_pool_ids(State(state): State<AppState>) -> ApiResult<Json<Vec<Hash>>> {
    let node = state.node.lock().await;
    Ok(Json(node.store.pool_ids().map_err(internal)?))
}

async fn get_pool_messages(
    State(state): State<AppState>,
    Json(ids): Json<Vec<Hash>>,
) -> ApiResult<Json<Vec<Message>>> {
    let node = state.node.lock().await;
    let ids = &ids[..ids.len().min(POOL_FETCH_LIMIT)];
    Ok(Json(node.store.pool_get(ids).map_err(internal)?))
}
