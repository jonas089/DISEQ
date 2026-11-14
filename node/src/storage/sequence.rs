//! The sequenced output: which messages each block contributed.
//!
//! A block's message sequence is its batches' messages in order, minus messages sequenced
//! before (in an earlier block, or earlier in the same block). The `messages` index answers
//! "was this message sequenced, and where"; `outputs` stores, per block, the positions that
//! were skipped as duplicates (almost always none), so the sequence can be rebuilt from the
//! stored batches without storing messages twice.
use super::{height_key, write_options, Db};
use anyhow::{anyhow, Result};
use diseq_consensus::types::{Batch, Hash, Message};
use rocksdb::WriteBatch;

const SEQUENCED_HEIGHT_KEY: &str = "sequenced_height";

impl Db {
    /// Height of the last block whose message sequence is final.
    pub fn sequenced_height(&self) -> Result<u32> {
        match self.meta_get(SEQUENCED_HEIGHT_KEY)? {
            Some(bytes) => Ok(bincode::deserialize(&bytes)?),
            None => Ok(0),
        }
    }

    /// For each id, whether the message was already sequenced.
    pub fn sequenced(&self, ids: &[Hash]) -> Result<Vec<bool>> {
        let cf = self.cf("messages");
        self.raw()
            .multi_get_cf(ids.iter().map(|id| (cf, id.as_slice())))
            .into_iter()
            .map(|r| Ok(r?.is_some()))
            .collect()
    }

    /// Height at which a message was sequenced.
    pub fn sequenced_at(&self, id: &Hash) -> Result<Option<u32>> {
        Ok(self
            .get("messages", id)?
            .map(|b| u32::from_be_bytes(b.as_slice().try_into().unwrap_or_default())))
    }

    /// Atomically records the output of block `height`: the included message ids and the
    /// skipped positions.
    pub fn record_output(&self, height: u32, included: &[Hash], skipped: &[u32]) -> Result<()> {
        let mut batch = WriteBatch::default();
        let messages = self.cf("messages");
        for id in included {
            batch.put_cf(messages, id, height_key(height));
        }
        batch.put_cf(
            self.cf("outputs"),
            height_key(height),
            bincode::serialize(skipped)?,
        );
        batch.put_cf(
            self.cf("meta"),
            SEQUENCED_HEIGHT_KEY,
            bincode::serialize(&height)?,
        );
        self.raw().write_opt(batch, &write_options(false))?;
        Ok(())
    }

    /// The message sequence of block `height`, or `None` if it is not sequenced yet.
    pub fn output(&self, height: u32, batch_digests: &[Hash]) -> Result<Option<Vec<Message>>> {
        let Some(skipped) = self.get("outputs", &height_key(height))? else {
            return Ok(None);
        };
        let skipped: Vec<u32> = bincode::deserialize(&skipped)?;
        let batches = self
            .batches(batch_digests)?
            .into_iter()
            .collect::<Option<Vec<Batch>>>()
            .ok_or_else(|| anyhow!("batch payload missing for sequenced block {height}"))?;
        Ok(Some(apply_skips(&batches, &skipped)))
    }
}

/// Concatenates the batches' messages, leaving out the positions in `skipped` (sorted).
pub fn apply_skips(batches: &[Batch], skipped: &[u32]) -> Vec<Message> {
    let mut skip = skipped.iter().peekable();
    batches
        .iter()
        .flat_map(|b| b.messages.iter())
        .enumerate()
        .filter(|(i, _)| {
            if skip.peek() == Some(&&(*i as u32)) {
                skip.next();
                false
            } else {
                true
            }
        })
        .map(|(_, m)| m.clone())
        .collect()
}
