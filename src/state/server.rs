//! SQLite persistence: committed blocks, the committed-message index, the mempool and the
//! latest Merkle trie root. All tables live in one database file.
use crate::types::{Block, Hash, Message};
use anyhow::{Context, Result};
use ciphercurve_trie::store::types::Root;
use rusqlite::{params, Connection, OptionalExtension};

pub struct Store {
    pub db_path: String,
}

impl Store {
    pub fn open(db_path: &str) -> Result<Self> {
        let store = Store {
            db_path: db_path.to_string(),
        };
        store.conn()?.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS blocks (
                 height INTEGER PRIMARY KEY,
                 hash BLOB NOT NULL,
                 block BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS committed_messages (
                 id BLOB PRIMARY KEY,
                 height INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS mempool (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 id BLOB NOT NULL UNIQUE,
                 message BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY,
                 value BLOB NOT NULL
             );",
        )?;
        Ok(store)
    }

    fn conn(&self) -> Result<Connection> {
        Connection::open(&self.db_path).context("failed to open database")
    }

    // ---- blocks -------------------------------------------------------------------------

    /// Inserts genesis if the chain is empty; fails if a different genesis is stored.
    pub fn init_genesis(&self, genesis: &Block) -> Result<()> {
        match self.block(0)? {
            Some(existing) => anyhow::ensure!(
                existing.hash() == genesis.hash(),
                "database contains a different genesis block"
            ),
            None => {
                self.conn()?.execute(
                    "INSERT INTO blocks (height, hash, block) VALUES (0, ?1, ?2)",
                    params![genesis.hash().to_vec(), bincode::serialize(genesis)?],
                )?;
            }
        }
        Ok(())
    }

    pub fn latest_height(&self) -> Result<u32> {
        Ok(self
            .conn()?
            .query_row("SELECT MAX(height) FROM blocks", [], |r| r.get::<_, u32>(0))?)
    }

    pub fn block(&self, height: u32) -> Result<Option<Block>> {
        let bytes: Option<Vec<u8>> = self
            .conn()?
            .query_row(
                "SELECT block FROM blocks WHERE height = ?1",
                [height],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match bytes {
            Some(b) => Some(bincode::deserialize(&b)?),
            None => None,
        })
    }

    pub fn latest_block(&self) -> Result<Block> {
        let height = self.latest_height()?;
        self.block(height)?.context("latest block missing")
    }

    /// Atomically stores a committed block, indexes its messages, removes them from the
    /// mempool and records the new trie root.
    pub fn commit_block(&self, block: &Block, trie_root: &Root) -> Result<()> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO blocks (height, hash, block) VALUES (?1, ?2, ?3)",
            params![
                block.height,
                block.hash().to_vec(),
                bincode::serialize(block)?
            ],
        )?;
        for message in &block.messages {
            let id = message.id().to_vec();
            tx.execute(
                "INSERT INTO committed_messages (id, height) VALUES (?1, ?2)",
                params![id, block.height],
            )?;
            tx.execute("DELETE FROM mempool WHERE id = ?1", params![id])?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('trie_root', ?1)",
            params![bincode::serialize(trie_root)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn is_committed(&self, id: &Hash) -> Result<bool> {
        Ok(self
            .conn()?
            .query_row(
                "SELECT 1 FROM committed_messages WHERE id = ?1",
                [id.to_vec()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn trie_root(&self) -> Result<Root> {
        let bytes: Option<Vec<u8>> = self
            .conn()?
            .query_row("SELECT value FROM meta WHERE key = 'trie_root'", [], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(match bytes {
            Some(b) => bincode::deserialize(&b)?,
            None => Root::empty(),
        })
    }

    // ---- consensus state (survives restarts so a validator never double-signs) -----------

    pub fn meta_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn()?
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn meta_put(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn()?.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    // ---- mempool ------------------------------------------------------------------------

    /// Adds a message unless it is already pooled or committed. Returns whether it was new.
    pub fn pool_insert(&self, message: &Message, max_pool_size: usize) -> Result<bool> {
        let id = message.id();
        if self.is_committed(&id)? {
            return Ok(false);
        }
        let conn = self.conn()?;
        let size: usize = conn.query_row("SELECT COUNT(*) FROM mempool", [], |r| r.get(0))?;
        let exists = conn
            .query_row("SELECT 1 FROM mempool WHERE id = ?1", [id.to_vec()], |_| {
                Ok(())
            })
            .optional()?
            .is_some();
        if exists {
            return Ok(false);
        }
        anyhow::ensure!(size < max_pool_size, "mempool is full");
        conn.execute(
            "INSERT OR IGNORE INTO mempool (id, message) VALUES (?1, ?2)",
            params![id.to_vec(), bincode::serialize(message)?],
        )?;
        Ok(conn.changes() == 1)
    }

    /// Oldest-first batch of pooled messages (FIFO sequencing).
    pub fn pool_batch(&self, limit: usize) -> Result<Vec<Message>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT message FROM mempool ORDER BY seq LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |r| r.get::<_, Vec<u8>>(0))?;
        rows.map(|r| Ok(bincode::deserialize(&r?)?)).collect()
    }

    pub fn pool_ids(&self) -> Result<Vec<Hash>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT id FROM mempool ORDER BY seq")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        rows.map(|r| {
            r?.try_into()
                .map_err(|_| anyhow::anyhow!("malformed message id"))
        })
        .collect()
    }

    pub fn pool_get(&self, ids: &[Hash]) -> Result<Vec<Message>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT message FROM mempool WHERE id = ?1")?;
        let mut messages = Vec::new();
        for id in ids {
            if let Some(bytes) = stmt
                .query_row([id.to_vec()], |r| r.get::<_, Vec<u8>>(0))
                .optional()?
            {
                messages.push(bincode::deserialize(&bytes)?);
            }
        }
        Ok(messages)
    }

    pub fn pool_contains(&self, id: &Hash) -> Result<bool> {
        Ok(self
            .conn()?
            .query_row("SELECT 1 FROM mempool WHERE id = ?1", [id.to_vec()], |_| {
                Ok(())
            })
            .optional()?
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let store = Store::open(path.to_str().unwrap()).unwrap();
        store.init_genesis(&Block::genesis(1)).unwrap();
        (dir, store)
    }

    fn msg(data: u8) -> Message {
        Message {
            data: vec![data],
            timestamp: 0,
        }
    }

    #[test]
    fn mempool_deduplicates_and_respects_commits() {
        let (_dir, store) = store();
        assert!(store.pool_insert(&msg(1), 10).unwrap());
        assert!(!store.pool_insert(&msg(1), 10).unwrap());
        // same payload, different timestamp: same id
        assert!(!store
            .pool_insert(
                &Message {
                    data: vec![1],
                    timestamp: 5
                },
                10
            )
            .unwrap());
        assert!(store.pool_insert(&msg(2), 10).unwrap());
        assert_eq!(store.pool_batch(10).unwrap(), vec![msg(1), msg(2)]);

        let mut block = Block::genesis(1);
        block.height = 1;
        block.messages = vec![msg(1)];
        store.commit_block(&block, &Root::empty()).unwrap();
        assert_eq!(store.pool_batch(10).unwrap(), vec![msg(2)]);
        // a committed message can never re-enter the pool
        assert!(!store.pool_insert(&msg(1), 10).unwrap());
        assert_eq!(store.latest_height().unwrap(), 1);
    }

    #[test]
    fn mempool_is_bounded() {
        let (_dir, store) = store();
        assert!(store.pool_insert(&msg(1), 1).unwrap());
        assert!(store.pool_insert(&msg(2), 1).is_err());
    }
}
