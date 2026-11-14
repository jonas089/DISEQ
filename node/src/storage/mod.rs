//! Persistence: one RocksDB database with a column family per concern.
//!
//! | Column family | Key → value                           | Written by          |
//! |---------------|---------------------------------------|---------------------|
//! | `blocks`      | height → block (ordering, certified)  | consensus writer    |
//! | `batch_index` | batch digest → height                 | consensus writer    |
//! | `meta`        | name → value (consensus state, ...)   | consensus writer    |
//! | `batches`     | batch digest → batch payload          | consensus writer    |
//! | `messages`    | message id → height it was sequenced  | sequencer           |
//! | `outputs`     | height → skipped message positions    | sequencer           |
//! | `trie_nodes`, `trie_meta` | Merkle trie               | trie writer         |
//!
//! RocksDB allows concurrent writers, so each stage writes its own column families from its
//! own thread. Writes that safety depends on (blocks, own votes) are synced to disk.
pub mod batches;
pub mod chain;
pub mod sequence;
pub mod trie;

use anyhow::{Context, Result};
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, Options, WriteOptions, DB};

const COLUMN_FAMILIES: [&str; 8] = [
    "blocks",
    "batch_index",
    "meta",
    "batches",
    "messages",
    "outputs",
    "trie_nodes",
    "trie_meta",
];

pub struct Db {
    db: DB,
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        options.increase_parallelism(4);
        let cfs = COLUMN_FAMILIES
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()));
        let db = DB::open_cf_descriptors(&options, path, cfs)
            .with_context(|| format!("failed to open database at {path}"))?;
        Ok(Db { db })
    }

    pub(crate) fn cf(&self, name: &str) -> &ColumnFamily {
        self.db.cf_handle(name).expect("column family exists")
    }

    pub(crate) fn raw(&self) -> &DB {
        &self.db
    }

    pub(crate) fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.db.get_cf(self.cf(cf), key)?)
    }

    pub(crate) fn meta_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.get("meta", key.as_bytes())
    }

    pub(crate) fn meta_put(&self, key: &str, value: &[u8], durable: bool) -> Result<()> {
        self.db
            .put_cf_opt(self.cf("meta"), key, value, &write_options(durable))?;
        Ok(())
    }
}

pub(crate) fn write_options(durable: bool) -> WriteOptions {
    let mut options = WriteOptions::default();
    options.set_sync(durable);
    options
}

/// Heights as big-endian keys so they sort numerically.
pub(crate) fn height_key(height: u32) -> [u8; 4] {
    height.to_be_bytes()
}
