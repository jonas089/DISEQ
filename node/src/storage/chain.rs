//! The consensus ledger: committed blocks, the committed-batch index and the validator's own
//! consensus state. Implements [`ConsensusStore`] for the consensus state machine.
use super::{height_key, write_options, Db};
use anyhow::{ensure, Context, Result};
use diseq_consensus::types::{Block, Hash};
use diseq_consensus::ConsensusStore;
use rocksdb::WriteBatch;
use std::sync::Arc;

const HEIGHT_KEY: &str = "height";
const CONSENSUS_STATE_KEY: &str = "consensus_state";

#[derive(Clone)]
pub struct ChainStore {
    db: Arc<Db>,
}

impl ChainStore {
    pub fn new(db: Arc<Db>) -> Self {
        ChainStore { db }
    }
}

impl ConsensusStore for ChainStore {
    fn block(&self, height: u32) -> Result<Option<Block>> {
        match self.db.get("blocks", &height_key(height))? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    fn latest_height(&self) -> Result<u32> {
        let bytes = self
            .db
            .meta_get(HEIGHT_KEY)?
            .context("chain is not initialized")?;
        Ok(bincode::deserialize(&bytes)?)
    }

    fn commit_block(&mut self, block: &Block) -> Result<()> {
        if block.height > 0 {
            ensure!(
                self.latest_height()? + 1 == block.height,
                "blocks must be committed in order"
            );
        }
        let digests: Vec<Hash> = block.batches.iter().map(|b| b.digest).collect();
        ensure!(
            !self.batches_committed(&digests)?.into_iter().any(|c| c),
            "batch committed twice"
        );
        let mut batch = WriteBatch::default();
        batch.put_cf(
            self.db.cf("blocks"),
            height_key(block.height),
            bincode::serialize(block)?,
        );
        for digest in &digests {
            batch.put_cf(self.db.cf("batch_index"), digest, height_key(block.height));
        }
        batch.put_cf(
            self.db.cf("meta"),
            HEIGHT_KEY,
            bincode::serialize(&block.height)?,
        );
        self.db.raw().write_opt(batch, &write_options(true))?;
        Ok(())
    }

    fn batches_committed(&self, digests: &[Hash]) -> Result<Vec<bool>> {
        let cf = self.db.cf("batch_index");
        self.db
            .raw()
            .multi_get_cf(digests.iter().map(|d| (cf, d.as_slice())))
            .into_iter()
            .map(|r| Ok(r?.is_some()))
            .collect()
    }

    fn load_state(&self) -> Result<Option<Vec<u8>>> {
        self.db.meta_get(CONSENSUS_STATE_KEY)
    }

    fn save_state(&mut self, state: &[u8]) -> Result<()> {
        self.db.meta_put(CONSENSUS_STATE_KEY, state, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diseq_consensus::types::BatchCert;

    #[test]
    fn commits_blocks_in_order_and_batches_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ChainStore::new(Arc::new(Db::open(dir.path().to_str().unwrap()).unwrap()));
        store.commit_block(&Block::genesis(1)).unwrap();
        let cert = |d: u8| BatchCert {
            digest: [d; 32],
            author: vec![],
            messages: 1,
            attestations: vec![],
        };
        let mut block = Block::genesis(1);
        block.height = 1;
        block.batches = vec![cert(1), cert(2)];
        store.commit_block(&block).unwrap();
        assert_eq!(store.latest_height().unwrap(), 1);
        assert_eq!(store.block(1).unwrap().unwrap(), block);
        assert_eq!(
            store.batches_committed(&[[2; 32], [3; 32]]).unwrap(),
            vec![true, false]
        );
        block.height = 2;
        block.batches = vec![cert(1)];
        assert!(store.commit_block(&block).is_err(), "batch committed twice");
        block.height = 3;
        block.batches = vec![];
        assert!(store.commit_block(&block).is_err(), "gap");
        assert_eq!(store.latest_height().unwrap(), 1);
    }
}
