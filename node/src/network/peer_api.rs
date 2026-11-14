//! HTTP routes served to other nodes (bincode only).
use super::{sync::BATCH_FETCH_LIMIT, wire, DataMsg, PeerMsg};
use crate::api::{bad_request, bincode_response, internal, overloaded, ApiResult, AppState};
use crate::runtime::{DataInput, Input};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
    routing::{get, post},
    Router,
};
use diseq_consensus::types::Hash;
use diseq_consensus::ConsensusStore;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/p2p/consensus", post(consensus))
        .route("/p2p/data", post(data))
        .route("/p2p/height", get(height))
        .route("/p2p/block/:height", get(block))
        .route("/p2p/batches", post(batches))
}

/// Proposals, votes, attestations and certificates; handed to the writer in order.
async fn consensus(State(state): State<AppState>, body: Bytes) -> ApiResult<&'static str> {
    let msgs: Vec<PeerMsg> = wire::decode(&body).map_err(bad_request)?;
    for msg in msgs {
        state
            .writer
            .send(Input::Peer(msg))
            .await
            .map_err(internal)?;
    }
    Ok("[Ok]")
}

/// Batches and forwarded client messages. Messages get their ids computed here, off the
/// writer thread.
async fn data(State(state): State<AppState>, body: Bytes) -> ApiResult<&'static str> {
    let msgs: Vec<DataMsg> = wire::decode(&body).map_err(bad_request)?;
    for msg in msgs {
        let input = match msg {
            DataMsg::Batch(batch) => DataInput::Batch(batch),
            DataMsg::Messages(messages) => DataInput::Messages {
                messages: messages.into_iter().map(|m| (m.id(), m)).collect(),
                reply: None,
            },
        };
        state.writer.try_data(input).map_err(overloaded)?;
    }
    Ok("[Ok]")
}

async fn height(State(state): State<AppState>) -> ApiResult<Response> {
    bincode_response(&state.chain.latest_height().map_err(internal)?)
}

async fn block(State(state): State<AppState>, Path(height): Path<u32>) -> ApiResult<Response> {
    match state.chain.block(height).map_err(internal)? {
        Some(block) => bincode_response(&block),
        None => Err((StatusCode::NOT_FOUND, "[Error] unknown block".into())),
    }
}

/// The requested batches this node stores.
async fn batches(State(state): State<AppState>, body: Bytes) -> ApiResult<Response> {
    let digests: Vec<Hash> = wire::decode(&body).map_err(bad_request)?;
    let digests: Vec<Hash> = digests.into_iter().take(BATCH_FETCH_LIMIT).collect();
    let found: Vec<_> = state
        .db
        .batches(&digests)
        .map_err(internal)?
        .into_iter()
        .flatten()
        .collect();
    bincode_response(&found)
}
