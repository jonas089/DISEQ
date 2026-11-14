//! Pull-based recovery: catching up on committed blocks, and fetching batch payloads.
use super::transport::Net;
use crate::runtime::Writer;
use crate::storage::chain::ChainStore;
use crate::{log_info, log_warn};
use anyhow::Result;
use diseq_consensus::types::{Batch, Block, Hash};
use diseq_consensus::ConsensusStore;
use std::collections::HashSet;

/// Batch digests per `/p2p/batches` request.
pub const BATCH_FETCH_LIMIT: usize = 64;

/// Fetches certified blocks from peers that are ahead and commits them through the writer
/// (which verifies each block's commit certificate).
pub async fn sync_blocks(
    writer: &Writer,
    chain: &ChainStore,
    net: &Net,
    peers: &[String],
) -> Result<()> {
    for peer in peers {
        let Ok(peer_height) = net.get::<u32>(peer, "/p2p/height").await else {
            continue;
        };
        loop {
            let next = chain.latest_height()? + 1;
            if next > peer_height {
                break;
            }
            let block: Block = match net.get(peer, &format!("/p2p/block/{next}")).await {
                Ok(block) => block,
                Err(_) => break,
            };
            match writer.certify(block).await {
                Ok(()) => log_info(format!("Synchronized block {next} from {peer}")),
                // committed via gossip in the meantime
                Err(_) if chain.latest_height()? >= next => continue,
                Err(e) => {
                    log_warn(format!("rejected block {next} from {peer}: {e:#}"));
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Asks peers for the batches with the given digests. Returns the ones obtained; each is
/// checked against its digest, so a peer cannot substitute content.
pub async fn fetch_batches(net: &Net, peers: &[String], digests: &[Hash]) -> Vec<Batch> {
    let mut wanted: HashSet<Hash> = digests.iter().copied().collect();
    let mut found = Vec::new();
    for peer in peers {
        if wanted.is_empty() {
            break;
        }
        let ask: Vec<Hash> = wanted.iter().take(BATCH_FETCH_LIMIT).copied().collect();
        let Ok(batches) = net.post::<_, Vec<Batch>>(peer, "/p2p/batches", &ask).await else {
            continue;
        };
        for batch in batches {
            if wanted.remove(&batch.digest()) {
                found.push(batch);
            }
        }
    }
    found
}
