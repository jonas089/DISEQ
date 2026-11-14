//! The storage consensus needs, as a trait, so the state machine does no I/O itself.
//!
//! The node implements it on RocksDB; [`MemStore`] is an in-memory implementation for tests
//! and simulations.
use crate::types::{Block, Hash};
use anyhow::{ensure, Result};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub trait ConsensusStore: Send {
    fn block(&self, height: u32) -> Result<Option<Block>>;
    fn latest_height(&self) -> Result<u32>;
    /// Durably and atomically stores a committed block and marks its batches as committed.
    /// Must fail if any of its batches was committed before.
    fn commit_block(&mut self, block: &Block) -> Result<()>;
    /// For each digest, whether a committed block already contains it.
    fn batches_committed(&self, digests: &[Hash]) -> Result<Vec<bool>>;
    /// The validator's own consensus state (locks, signed votes) for the height in progress.
    fn load_state(&self) -> Result<Option<Vec<u8>>>;
    /// Must be durable when it returns: votes are sent only after their state is saved.
    fn save_state(&mut self, state: &[u8]) -> Result<()>;
}

#[derive(Default)]
struct Inner {
    blocks: Vec<Block>,
    batches: HashSet<Hash>,
    state: Option<Vec<u8>>,
}

/// In-memory store. Clones share the same data, which lets tests "restart" a node.
#[derive(Clone, Default)]
pub struct MemStore(Arc<Mutex<Inner>>);

impl ConsensusStore for MemStore {
    fn block(&self, height: u32) -> Result<Option<Block>> {
        Ok(self.0.lock().unwrap().blocks.get(height as usize).cloned())
    }
    fn latest_height(&self) -> Result<u32> {
        let blocks = &self.0.lock().unwrap().blocks;
        ensure!(!blocks.is_empty(), "no genesis");
        Ok(blocks.len() as u32 - 1)
    }
    fn commit_block(&mut self, block: &Block) -> Result<()> {
        let mut inner = self.0.lock().unwrap();
        ensure!(
            block.height as usize == inner.blocks.len(),
            "blocks must be committed in order"
        );
        let digests: HashMap<Hash, ()> = block.batches.iter().map(|b| (b.digest, ())).collect();
        ensure!(
            digests.len() == block.batches.len()
                && digests.keys().all(|d| !inner.batches.contains(d)),
            "batch committed twice"
        );
        inner.batches.extend(digests.into_keys());
        inner.blocks.push(block.clone());
        Ok(())
    }
    fn batches_committed(&self, digests: &[Hash]) -> Result<Vec<bool>> {
        let inner = self.0.lock().unwrap();
        Ok(digests.iter().map(|d| inner.batches.contains(d)).collect())
    }
    fn load_state(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().state.clone())
    }
    fn save_state(&mut self, state: &[u8]) -> Result<()> {
        self.0.lock().unwrap().state = Some(state.to_vec());
        Ok(())
    }
}
