//! Merkle trie over all sequenced message ids, maintained off the consensus path.
//!
//! The sequencer hands each block's newly sequenced message ids to [`TrieService`], a single
//! writer thread. Whatever is queued is inserted as one batch ([`ciphercurve_trie`] reads each
//! touched node once and hashes it once) and written together with the new root and height
//! in one RocksDB write, so the trie always reflects a prefix of the sequence.
//!
//! The trie is a set: key and value hash are both the message id.
use super::{write_options, Db};
use anyhow::{anyhow, Context, Result};
use ciphercurve_trie::{insert_batch, prove, NodeStore, Proof, EMPTY_ROOT};
use diseq_consensus::types::Hash;
use rocksdb::WriteBatch;
use std::sync::{mpsc, Arc};
use tokio::sync::oneshot;

const ROOT_KEY: &[u8] = b"root";
const HEIGHT_KEY: &[u8] = b"height";

struct Nodes<'a>(&'a Db);
impl NodeStore for Nodes<'_> {
    fn get(&self, hash: &Hash) -> Result<Option<Vec<u8>>> {
        self.0.get("trie_nodes", hash)
    }
}

/// (root, height of the last block included)
fn state(db: &Db) -> Result<(Hash, u32)> {
    let root = match db.get("trie_meta", ROOT_KEY)? {
        Some(b) => b.as_slice().try_into().context("bad trie root")?,
        None => EMPTY_ROOT,
    };
    let height = match db.get("trie_meta", HEIGHT_KEY)? {
        Some(b) => u32::from_be_bytes(b.as_slice().try_into().context("bad trie height")?),
        None => 0,
    };
    Ok((root, height))
}

/// Inserts `ids` on top of `root` and records `height`, atomically.
fn apply(db: &Db, root: Hash, height: u32, ids: &[Hash]) -> Result<Hash> {
    let items: Vec<(Hash, Hash)> = ids.iter().map(|id| (*id, *id)).collect();
    let update = insert_batch(&Nodes(db), root, &items)?;
    let mut batch = WriteBatch::default();
    let nodes = db.cf("trie_nodes");
    for (hash, bytes) in &update.new_nodes {
        batch.put_cf(nodes, hash, bytes);
    }
    batch.put_cf(db.cf("trie_meta"), ROOT_KEY, update.root);
    batch.put_cf(db.cf("trie_meta"), HEIGHT_KEY, height.to_be_bytes());
    db.raw().write_opt(batch, &write_options(false))?;
    Ok(update.root)
}

enum Command {
    Apply(u32, Vec<Hash>),
    Root(oneshot::Sender<(Hash, u32)>),
    Proof(Hash, oneshot::Sender<Result<Option<Proof>>>),
}

/// Handle to the trie writer thread.
#[derive(Clone)]
pub struct TrieService {
    tx: mpsc::Sender<Command>,
}

impl TrieService {
    /// Starts the writer; the sequencer replays blocks the trie is missing.
    pub fn start(db: Arc<Db>) -> Result<(Self, u32)> {
        let (root, height) = state(&db)?;
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("trie-writer".into())
            .spawn(move || run(db, root, height, rx))?;
        Ok((TrieService { tx }, height))
    }

    /// Queues the message ids sequenced in block `height` (heights in order, no gaps).
    pub fn apply(&self, height: u32, ids: Vec<Hash>) {
        let _ = self.tx.send(Command::Apply(height, ids));
    }

    /// Current root and the height it reflects.
    pub async fn root(&self) -> Result<(Hash, u32)> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Root(tx))
            .map_err(|_| anyhow!("trie writer stopped"))?;
        Ok(rx.await?)
    }

    /// Membership proof for a message id against the current root.
    pub async fn proof(&self, id: Hash) -> Result<Option<Proof>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Proof(id, tx))
            .map_err(|_| anyhow!("trie writer stopped"))?;
        rx.await?
    }
}

fn run(db: Arc<Db>, mut root: Hash, mut height: u32, rx: mpsc::Receiver<Command>) {
    let mut queries = Vec::new();
    while let Ok(first) = rx.recv() {
        // drain everything queued: all pending blocks go into one batch
        let mut ids = Vec::new();
        let mut new_height = height;
        for cmd in std::iter::once(first).chain(rx.try_iter()) {
            match cmd {
                Command::Apply(h, block_ids) if h == new_height + 1 => {
                    new_height = h;
                    ids.extend(block_ids);
                }
                Command::Apply(h, _) if h <= new_height => {} // replayed twice
                Command::Apply(h, _) => crate::log_warn(format!(
                    "trie writer: block {h} out of order, expected {}",
                    new_height + 1
                )),
                query => queries.push(query),
            }
        }
        if new_height > height {
            match apply(&db, root, new_height, &ids) {
                Ok(r) => (root, height) = (r, new_height),
                Err(e) => {
                    // stop rather than build on a wrong root; restart resumes from disk
                    crate::log_warn(format!("trie update failed, trie writer stopped: {e:#}"));
                    return;
                }
            }
        }
        for query in queries.drain(..) {
            match query {
                Command::Root(reply) => {
                    let _ = reply.send((root, height));
                }
                Command::Proof(id, reply) => {
                    let _ = reply.send(prove(&Nodes(&db), root, &id));
                }
                Command::Apply(..) => unreachable!(),
            }
        }
    }
}
