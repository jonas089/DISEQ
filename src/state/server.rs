use crate::{
    config::consensus::{
        v1_sk_deserialized, v1_vk_deserialized, v2_sk_deserialized, v3_sk_deserialized,
        v3_vk_deserialized, v4_sk_deserialized, v4_vk_deserialized,
    },
    types::{Block, ConsensusCommitment, Message, Timestamp},
};
use k256::ecdsa::{SigningKey, VerifyingKey};
use rusqlite::{params, Connection};
use std::env;
pub trait SqLiteBlockStore {
    fn setup(&self);
    fn block_exists(&self, height: u32) -> bool;
    fn trigger_genesis(&mut self, timestamp: Timestamp);
    fn insert_block(&mut self, previous_height: u32, block: Block);
    fn get_block_by_height(&self, height: u32) -> Block;
    fn current_block_height(&self) -> u32;
}
pub struct BlockStore {
    pub db_path: String,
}
impl SqLiteBlockStore for BlockStore {
    fn setup(&self) {
        let conn = Connection::open(&self.db_path).unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS blocks (
            height BLOB PRIMARY KEY,
            block BLOB NOT NULL
            )",
            [],
        )
        .unwrap();
    }
    fn block_exists(&self, height: u32) -> bool {
        let conn = Connection::open(&self.db_path).unwrap();
        let mut stmt = conn
            .prepare("SELECT EXISTS(SELECT 1 FROM blocks WHERE height = ?1)")
            .unwrap();
        let exists: bool = stmt.query_row([&height], |row| row.get(0)).unwrap_or(false);
        exists
    }
    fn current_block_height(&self) -> u32 {
        let conn = Connection::open(&self.db_path).unwrap();
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM blocks").unwrap();
        let mut rows = stmt.query([]).unwrap();
        let count: usize = rows.next().unwrap().unwrap().get(0).unwrap();
        count as u32
    }
    fn get_block_by_height(&self, height: u32) -> Block {
        let conn = Connection::open(&self.db_path).unwrap();
        let mut stmt = conn
            .prepare("SELECT block FROM blocks WHERE height = ?1 LIMIT 1")
            .unwrap();
        let block_serialized: Option<Vec<u8>> = stmt
            .query_row([&height], |row| {
                let block_serialized: Vec<u8> = row.get(0).unwrap();
                Ok(Some(block_serialized))
            })
            .unwrap_or(None);
        // todo: don't expect this
        bincode::deserialize(
            &block_serialized.expect(&format!("[Error] Block not found: {}", &height)),
        )
        .unwrap()
    }
    fn insert_block(&mut self, height: u32, block: Block) {
        let conn = Connection::open(&self.db_path).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO blocks (height, block) VALUES (?1, ?2)",
            params![height, bincode::serialize(&block).unwrap()],
        )
        .unwrap();
    }
    fn trigger_genesis(&mut self, timestamp: Timestamp) {
        self.insert_block(
            0u32,
            Block {
                timestamp,
                height: 0,
                signature: Some(vec![]),
                messages: vec![],
                commitments: None,
            },
        )
    }
}

// note: can be used for other dbs and should therefore be renamed
pub trait SqLiteMessagePool {
    fn setup(&self);
    fn insert_message(&mut self, message: Message);
    fn get_message_by_index(&self, index: u32) -> Message;
    fn get_all_messages(&self) -> Vec<Message>;
    fn reinitialize(&mut self);
}
pub struct MessagePool {
    pub size: u32,
    pub db_path: String,
}
impl SqLiteMessagePool for MessagePool {
    fn setup(&self) {
        let conn = Connection::open(&self.db_path).unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS txns (
                uid BLOB PRIMARY KEY,
                tx BLOB NOT NULL
            )",
            [],
        )
        .unwrap();
    }
    fn get_message_by_index(&self, index: u32) -> Message {
        let conn = Connection::open(&self.db_path).unwrap();
        let mut stmt = conn
            .prepare("SELECT tx FROM txns WHERE uid = ?1 LIMIT 1")
            .unwrap();

        let message_serialized: Option<Vec<u8>> = stmt
            .query_row([&index], |row| {
                let node_serialized: Vec<u8> = row.get(0).unwrap();
                Ok(Some(node_serialized))
            })
            .unwrap_or(None);

        bincode::deserialize(&message_serialized.expect("[Error] Block not found")).unwrap()
    }
    fn get_all_messages(&self) -> Vec<Message> {
        let conn = Connection::open(&self.db_path).unwrap();
        let mut stmt = conn.prepare("SELECT tx FROM txns").unwrap();
        let message_iter = stmt
            .query_map([], |row| {
                let message_blob: Vec<u8> = row.get(0)?;
                // Deserialize the BLOB back into a Message
                let message: Message = bincode::deserialize(&message_blob).unwrap();
                Ok(message)
            })
            .unwrap();
        let mut messages = Vec::new();
        for message in message_iter {
            messages.push(message.unwrap());
        }
        messages
    }
    fn insert_message(&mut self, message: Message) {
        let conn = Connection::open(&self.db_path).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO txns (tx) VALUES (?1)",
            params![bincode::serialize(&message).unwrap()],
        )
        .unwrap();
        // todo: read size from db
        self.size += 1;
    }
    fn reinitialize(&mut self) {
        // todo: remove when reading size from db
        self.size = 0;
        let conn = Connection::open(&self.db_path).unwrap();
        conn.execute("DROP TABLE IF EXISTS txns", []).unwrap();
        self.setup();
    }
}

pub struct InMemoryConsensus {
    pub validators: Vec<VerifyingKey>,
    pub local_validator: VerifyingKey,
    pub local_signing_key: SigningKey,
    pub commitments: Vec<Vec<ConsensusCommitment>>,
    pub round_winner: Option<VerifyingKey>,
    pub proposed: bool,
    pub committed: bool,
    pub signed: bool,
    pub lowest_block: Option<Vec<u8>>,
}
impl InMemoryConsensus {
    #[allow(unused)]
    pub fn empty() -> Self {
        Self {
            validators: Vec::new(),
            local_validator: v1_vk_deserialized(),
            local_signing_key: v2_sk_deserialized(),
            commitments: Vec::new(),
            round_winner: None,
            proposed: false,
            committed: false,
            signed: false,
            lowest_block: None,
        }
    }
    pub fn empty_with_default_validators() -> InMemoryConsensus {
        use crate::config::consensus::v2_vk_deserialized;
        let local_validator_test_id = env::var("LOCAL_VALIDATOR").unwrap_or(0.to_string());
        let local_validator = if local_validator_test_id == "0" {
            (v1_sk_deserialized(), v1_vk_deserialized())
        } else if local_validator_test_id == "1" {
            (v2_sk_deserialized(), v2_vk_deserialized())
        } else if local_validator_test_id == "2" {
            (v3_sk_deserialized(), v3_vk_deserialized())
        } else {
            (v4_sk_deserialized(), v4_vk_deserialized())
        };
        Self {
            validators: vec![
                v1_vk_deserialized(),
                v2_vk_deserialized(),
                v3_vk_deserialized(),
                v4_vk_deserialized(),
            ],
            local_validator: local_validator.1,
            local_signing_key: local_validator.0,
            commitments: Vec::new(),
            round_winner: None,
            proposed: false,
            committed: false,
            signed: false,
            lowest_block: None,
        }
    }
    pub fn reinitialize(&mut self) {
        self.commitments = Vec::new();
        self.round_winner = None;
        self.proposed = false;
        self.committed = false;
        self.signed = false;
        self.lowest_block = None;
    }
}
