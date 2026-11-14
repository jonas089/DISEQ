//! The sequencer: turns committed blocks (ordered batch certificates) into the final message
//! sequence. Runs after consensus, on its own task, so consensus never waits for payloads.
//!
//! For each committed block, in height order:
//!
//! 1. Load the block's batches. A missing batch (this node did not receive it) is fetched
//!    from peers; the certificate guarantees an honest validator holds it.
//! 2. Concatenate their messages and drop every message that was sequenced before, in an
//!    earlier block or earlier in this block. The result depends only on the chain, so every
//!    node derives the same sequence. This is the only place duplicates are resolved:
//!    the same message may legitimately sit in several batches (a client sent it to two
//!    validators, or retried).
//! 3. Atomically record the included ids and skipped positions, then feed the ids to the
//!    Merkle trie.
//!
//! The sequenced height (`/get/height`) trails the consensus height by the time this takes.
use crate::network::{sync::fetch_batches, transport::Net};
use crate::storage::{trie::TrieService, Db};
use crate::{log_info, log_warn};
use anyhow::{ensure, Result};
use diseq_consensus::types::{Batch, Block, Hash, Message};
use diseq_consensus::ConsensusStore;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;

pub struct Sequencer {
    pub db: Arc<Db>,
    pub chain: crate::storage::chain::ChainStore,
    pub trie: TrieService,
    pub net: Net,
    /// peers to fetch missing batches from (kept current by the writer)
    pub peers: Arc<RwLock<Vec<String>>>,
}

impl Sequencer {
    /// Catches up on blocks committed before a restart, then sequences blocks as they commit.
    pub async fn run(self, trie_height: u32, mut committed: mpsc::UnboundedReceiver<Block>) {
        if let Err(e) = self.catch_up(trie_height).await {
            log_warn(format!("sequencer stopped: {e:#}"));
            return;
        }
        while let Some(block) = committed.recv().await {
            // blocks replayed during catch-up may arrive again
            match self.db.sequenced_height() {
                Ok(h) if block.height <= h => continue,
                Ok(_) => {}
                Err(e) => {
                    log_warn(format!("sequencer stopped: {e:#}"));
                    return;
                }
            }
            if let Err(e) = self.sequence(block).await {
                log_warn(format!("sequencer stopped: {e:#}"));
                return;
            }
        }
    }

    async fn catch_up(&self, trie_height: u32) -> Result<()> {
        let sequenced = self.db.sequenced_height()?;
        // the trie may trail the sequence after a crash: re-feed it from stored outputs
        for height in trie_height + 1..=sequenced {
            let block = self
                .chain
                .block(height)?
                .ok_or_else(|| anyhow::anyhow!("gap"))?;
            let digests: Vec<Hash> = block.batches.iter().map(|b| b.digest).collect();
            let messages = self.db.output(height, &digests)?.unwrap_or_default();
            self.trie
                .apply(height, messages.iter().map(Message::id).collect());
        }
        for height in sequenced + 1..=self.chain.latest_height()? {
            let block = self
                .chain
                .block(height)?
                .ok_or_else(|| anyhow::anyhow!("gap"))?;
            self.sequence(block).await?;
        }
        Ok(())
    }

    async fn sequence(&self, block: Block) -> Result<()> {
        let height = block.height;
        ensure!(
            height == self.db.sequenced_height()? + 1,
            "sequencer out of order at {height}"
        );
        let batches = self.load_batches(&block).await?;
        let db = self.db.clone();
        let (included, skipped) =
            tokio::task::spawn_blocking(move || resolve(&db, height, &batches)).await??;
        if !skipped.is_empty() {
            log_info(format!(
                "Sequenced block {height}: {} messages, {} duplicates skipped",
                included.len(),
                skipped.len()
            ));
        }
        self.trie.apply(height, included);
        Ok(())
    }

    /// The block's batches in order, fetching missing ones until every one is available.
    async fn load_batches(&self, block: &Block) -> Result<Vec<Batch>> {
        let digests: Vec<Hash> = block.batches.iter().map(|b| b.digest).collect();
        let mut attempt = 0u32;
        loop {
            let slots = self.db.batches(&digests)?;
            let missing: Vec<Hash> = digests
                .iter()
                .zip(&slots)
                .filter(|(_, s)| s.is_none())
                .map(|(d, _)| *d)
                .collect();
            if missing.is_empty() {
                return Ok(slots.into_iter().map(|s| s.expect("present")).collect());
            }
            let peers = self.peers.read().expect("peers lock").clone();
            for batch in fetch_batches(&self.net, &peers, &missing).await {
                self.db.put_batch(&batch.digest(), &batch)?;
            }
            attempt += 1;
            if attempt.is_multiple_of(10) {
                log_warn(format!(
                    "block {}: still missing {} batches",
                    block.height,
                    missing.len()
                ));
            }
            tokio::time::sleep(Duration::from_millis(50 * attempt.min(20) as u64)).await;
        }
    }
}

/// Deduplicates a block's messages against everything sequenced before and records the
/// output. Returns (included ids, skipped positions).
fn resolve(db: &Db, height: u32, batches: &[Batch]) -> Result<(Vec<Hash>, Vec<u32>)> {
    let ids: Vec<Hash> = batches
        .iter()
        .flat_map(|b| b.messages.iter().map(Message::id))
        .collect();
    let already = db.sequenced(&ids)?;
    let mut seen = HashSet::with_capacity(ids.len());
    let mut included = Vec::with_capacity(ids.len());
    let mut skipped = Vec::new();
    for (pos, (id, already)) in ids.into_iter().zip(already).enumerate() {
        if already || !seen.insert(id) {
            skipped.push(pos as u32);
        } else {
            included.push(id);
        }
    }
    db.record_output(height, &included, &skipped)?;
    Ok((included, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::sequence::apply_skips;

    fn batch(seq: u64, data: &[&str]) -> Batch {
        Batch {
            author: vec![],
            seq,
            messages: data
                .iter()
                .map(|d| Message {
                    data: d.as_bytes().to_vec(),
                    timestamp: 0,
                })
                .collect(),
            signature: vec![],
        }
    }

    #[test]
    fn duplicates_are_sequenced_once_at_their_first_position() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_str().unwrap()).unwrap();
        // block 1: "b" twice across two batches
        let b1 = [batch(1, &["a", "b"]), batch(2, &["b", "c"])];
        let (included, skipped) = resolve(&db, 1, &b1).unwrap();
        assert_eq!(skipped, vec![2]);
        assert_eq!(included.len(), 3);
        let data = |msgs: Vec<Message>| msgs.into_iter().map(|m| m.data).collect::<Vec<_>>();
        assert_eq!(
            data(apply_skips(&b1, &skipped)),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
        // block 2: "a" was sequenced in block 1
        let b2 = [batch(3, &["a", "d"])];
        let (_, skipped) = resolve(&db, 2, &b2).unwrap();
        assert_eq!(skipped, vec![0]);
        assert_eq!(db.sequenced_height().unwrap(), 2);
        assert_eq!(db.sequenced_at(&b2[0].messages[1].id()).unwrap(), Some(2));
        assert_eq!(db.sequenced_at(&b1[0].messages[0].id()).unwrap(), Some(1));
    }
}
