use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};
pub type GenericSignature = Vec<u8>;
pub type Timestamp = u32;
pub type GenericMessageData = Vec<u8>;
pub type GenericPublicKey = Vec<u8>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub height: u32,
    pub messages: Vec<Message>,
    pub signature: Option<GenericSignature>,
    pub commitments: Option<Vec<BlockCommitment>>,
    pub timestamp: Timestamp,
}
impl Block {
    pub fn to_bytes(&self) -> Vec<u8> {
        let temp_block: Block = Block {
            height: self.height,
            messages: self.messages.clone(),
            signature: None,
            commitments: None,
            timestamp: self.timestamp,
        };
        bincode::serialize(&temp_block).unwrap()
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    pub data: GenericMessageData,
    pub timestamp: Timestamp,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockCommitment {
    // a signature over the serialized
    // messages in the Block
    pub signature: GenericSignature,
    pub validator: GenericPublicKey,
    pub timestamp: Timestamp,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConsensusCommitment {
    pub validator: GenericPublicKey,
    pub receipt: Receipt,
}
