//! Client HTTP API: JSON, plus bincode request bodies with
//! `Content-Type: application/octet-stream` for high-rate clients.
//!
//! Submitting a message returns once the node has accepted it; it is final once
//! `GET /get/message/:id` reports a height. Peer routes live in [`crate::network::peer_api`].
use crate::network::{peer_api, wire};
use crate::runtime::Writer;
use crate::storage::{chain::ChainStore, trie::TrieService, Db};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use diseq_consensus::types::{Block, Hash, Message};
use diseq_consensus::{ConsensusStore, Received};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub writer: Writer,
    pub db: Arc<Db>,
    pub chain: ChainStore,
    pub trie: TrieService,
    pub max_message_bytes: usize,
}

pub type ApiResult<T> = Result<T, (StatusCode, String)>;

pub fn bad_request(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, format!("[Error] {e:#}"))
}
pub fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("[Error] {e:#}"))
}
pub fn overloaded(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::SERVICE_UNAVAILABLE, format!("[Error] {e:#}"))
}

pub fn bincode_response<T: Serialize>(value: &T) -> ApiResult<Response> {
    let bytes = wire::encode(value).map_err(internal)?;
    Ok(([(header::CONTENT_TYPE, wire::BINCODE)], bytes).into_response())
}

/// Decodes a JSON or (with the bincode content type) bincode body.
fn decode_body<T: DeserializeOwned>(headers: &HeaderMap, body: &[u8]) -> ApiResult<T> {
    let is_bincode = headers
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes() == wire::BINCODE.as_bytes());
    if is_bincode {
        wire::decode(body).map_err(bad_request)
    } else {
        serde_json::from_slice(body).map_err(bad_request)
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/schedule", post(schedule))
        .route("/schedule/batch", post(schedule_batch))
        .route("/get/height", get(height))
        .route("/get/status", get(status))
        .route("/get/block/:height", get(block))
        .route("/get/message/:id", get(message))
        .route("/get/state_root", get(state_root))
        .route("/merkle_proof/:id", get(merkle_proof))
        .route("/get/validators", get(validators))
        .merge(peer_api::routes())
        .layer(DefaultBodyLimit::max(wire::MAX_WIRE_BYTES as usize))
        .with_state(state)
}

fn prepare(state: &AppState, messages: Vec<Message>) -> ApiResult<Vec<(Hash, Message)>> {
    messages
        .into_iter()
        .map(|m| {
            if m.data.is_empty() || m.data.len() > state.max_message_bytes {
                return Err(bad_request(format!(
                    "message must hold 1 to {} bytes",
                    state.max_message_bytes
                )));
            }
            Ok((m.id(), m))
        })
        .collect()
}

fn parse_id(hex_id: &str) -> ApiResult<Hash> {
    hex::decode(hex_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad_request("id must be 32 bytes of hex"))
}

async fn schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<String> {
    let message: Message = decode_body(&headers, &body)?;
    let batch = prepare(&state, vec![message])?;
    let id = hex::encode(batch[0].0);
    let verdict = state
        .writer
        .submit(batch)
        .await
        .map_err(overloaded)?
        .pop()
        .ok_or_else(|| internal("no verdict"))?;
    match verdict.map_err(overloaded)? {
        Received::New => Ok(format!("[Ok] Message is being sequenced: {id}")),
        Received::Duplicate => Ok(format!("[Ok] Message already known: {id}")),
    }
}

#[derive(Serialize, Default)]
struct BatchSummary {
    new: usize,
    duplicate: usize,
    rejected: Vec<(usize, String)>,
}

async fn schedule_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<BatchSummary>> {
    let messages: Vec<Message> = decode_body(&headers, &body)?;
    let batch = prepare(&state, messages)?;
    let verdicts = state.writer.submit(batch).await.map_err(overloaded)?;
    let mut summary = BatchSummary::default();
    for (i, v) in verdicts.into_iter().enumerate() {
        match v {
            Ok(Received::New) => summary.new += 1,
            Ok(Received::Duplicate) => summary.duplicate += 1,
            Err(e) => summary.rejected.push((i, e)),
        }
    }
    Ok(Json(summary))
}

/// Height of the last block whose message sequence is final.
async fn height(State(state): State<AppState>) -> ApiResult<Json<u32>> {
    Ok(Json(state.db.sequenced_height().map_err(internal)?))
}

#[derive(Serialize)]
struct Status {
    consensus_height: u32,
    sequenced_height: u32,
    trie_height: u32,
    pending_messages: usize,
    inflight_batches: usize,
    pending_certificates: usize,
}

async fn status(State(state): State<AppState>) -> ApiResult<Json<Status>> {
    let (pending_messages, inflight_batches, pending_certificates) = state
        .writer
        .query(|core| {
            (
                core.dissemination.pending_len(),
                core.dissemination.inflight(),
                core.consensus.pending_batches(),
            )
        })
        .await
        .map_err(internal)?;
    Ok(Json(Status {
        consensus_height: state.chain.latest_height().map_err(internal)?,
        sequenced_height: state.db.sequenced_height().map_err(internal)?,
        trie_height: state.trie.root().await.map_err(internal)?.1,
        pending_messages,
        inflight_batches,
        pending_certificates,
    }))
}

#[derive(Serialize)]
struct BlockView {
    #[serde(flatten)]
    block: Block,
    /// The block's final message sequence; `None` until the block is sequenced.
    messages: Option<Vec<Message>>,
}

async fn block(State(state): State<AppState>, Path(height): Path<u32>) -> ApiResult<Response> {
    let Some(block) = state.chain.block(height).map_err(internal)? else {
        return Ok("[Warning] Requested Block that does not exist".into_response());
    };
    let digests: Vec<Hash> = block.batches.iter().map(|b| b.digest).collect();
    let messages = state.db.output(height, &digests).map_err(internal)?;
    Ok(Json(BlockView { block, messages }).into_response())
}

#[derive(Serialize)]
struct MessageStatus {
    /// height of the block that sequenced the message, once final
    sequenced_at: Option<u32>,
}

async fn message(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<MessageStatus>> {
    let id = parse_id(&id)?;
    Ok(Json(MessageStatus {
        sequenced_at: state.db.sequenced_at(&id).map_err(internal)?,
    }))
}

#[derive(Serialize)]
struct StateRoot {
    /// hex root of the Merkle trie over all sequenced message ids
    root: String,
    /// height of the last block the root includes (the trie trails the sequence slightly)
    height: u32,
}

async fn state_root(State(state): State<AppState>) -> ApiResult<Json<StateRoot>> {
    let (root, height) = state.trie.root().await.map_err(internal)?;
    Ok(Json(StateRoot {
        root: hex::encode(root),
        height,
    }))
}

#[derive(Serialize)]
struct ProofStepView {
    prefix_len: u8,
    bitmap: u16,
    siblings: Vec<String>,
}

#[derive(Serialize)]
struct ProofView {
    root: String,
    height: u32,
    /// verify with `ciphercurve_trie::verify(root, id, id, proof)`
    steps: Vec<ProofStepView>,
}

/// Membership proof of a sequenced message id against the current state root.
async fn merkle_proof(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let id = parse_id(&id)?;
    let (root, height) = state.trie.root().await.map_err(internal)?;
    match state.trie.proof(id).await.map_err(internal)? {
        None => Err((
            StatusCode::NOT_FOUND,
            "[Error] message is not in the trie (yet)".into(),
        )),
        Some(proof) => Ok(Json(ProofView {
            root: hex::encode(root),
            height,
            steps: proof
                .steps
                .into_iter()
                .map(|s| ProofStepView {
                    prefix_len: s.prefix_len,
                    bitmap: s.bitmap,
                    siblings: s.siblings.iter().map(hex::encode).collect(),
                })
                .collect(),
        })
        .into_response()),
    }
}

#[derive(Serialize)]
struct ValidatorInfo {
    id: String,
    vrf_key: String,
    weight: u64,
    address: String,
}

async fn validators(State(state): State<AppState>) -> ApiResult<Json<Vec<ValidatorInfo>>> {
    let set = state
        .writer
        .query(|core| core.consensus.current_validators())
        .await
        .map_err(internal)?;
    Ok(Json(
        set.iter()
            .map(|v| ValidatorInfo {
                id: hex::encode(v.id_bytes()),
                vrf_key: hex::encode(&v.vrf_key),
                weight: v.weight,
                address: v.address.clone(),
            })
            .collect(),
    ))
}
