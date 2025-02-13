use crate::crypto::ecdsa::{deserialize_sk, deserialize_vk};
use k256::ecdsa::{SigningKey, VerifyingKey};

// time before a new block is created, from a block's timestamp onwards
// specified in seconds
pub const CLEARING_PHASE: u32 = 60;
pub const ROUND_DURATION: u32 = 120; // total duration CLEARING PHASE + ROUND_DURATION!
pub const CONSENSUS_THRESHOLD: u32 = 3;
pub const GOSSIP_PROPOSAL_RETRY_LIMIT_PER_PEER: u32 = 10;

pub const TEST_V1_SK: &[u8] = &[
    197, 131, 252, 199, 111, 171, 195, 194, 6, 111, 156, 165, 24, 173, 168, 49, 220, 204, 234, 73,
    99, 125, 215, 189, 192, 254, 218, 47, 55, 40, 214, 117,
];
pub const TEST_V1_VK: &[u8] = &[
    2, 145, 6, 132, 63, 12, 220, 31, 107, 229, 80, 59, 38, 153, 140, 235, 182, 43, 206, 83, 189, 7,
    223, 91, 52, 126, 122, 10, 55, 62, 238, 7, 219,
];
pub const TEST_V2_SK: &[u8] = &[
    31, 133, 86, 165, 209, 28, 9, 200, 44, 211, 32, 243, 68, 35, 181, 101, 112, 158, 112, 89, 132,
    37, 223, 101, 46, 64, 204, 23, 247, 13, 207, 129,
];
pub const TEST_V2_VK: &[u8] = &[
    2, 117, 224, 184, 15, 207, 177, 48, 93, 85, 52, 230, 31, 123, 67, 27, 47, 58, 245, 197, 215,
    189, 128, 192, 14, 203, 86, 139, 85, 234, 68, 42, 148,
];
pub const TEST_V3_SK: &[u8] = &[
    78, 194, 130, 103, 15, 45, 121, 75, 122, 24, 22, 185, 195, 164, 25, 189, 183, 163, 231, 221,
    37, 26, 101, 13, 69, 29, 77, 206, 217, 20, 77, 21,
];
pub const TEST_V3_VK: &[u8] = &[
    2, 217, 50, 215, 153, 42, 245, 61, 71, 110, 21, 55, 183, 0, 19, 78, 156, 8, 121, 68, 11, 122,
    51, 85, 220, 37, 239, 242, 201, 160, 77, 125, 239,
];
pub const TEST_V4_SK: &[u8] = &[
    9, 104, 30, 6, 93, 140, 7, 212, 211, 42, 112, 63, 19, 114, 222, 151, 216, 159, 111, 1, 72, 50,
    218, 221, 135, 152, 242, 175, 208, 8, 82, 16,
];
pub const TEST_V4_VK: &[u8] = &[
    2, 224, 125, 18, 54, 62, 252, 187, 84, 81, 249, 80, 161, 32, 46, 212, 182, 246, 46, 4, 182,
    124, 62, 192, 144, 236, 185, 255, 179, 94, 0, 46, 190,
];
pub fn v1_sk_deserialized() -> SigningKey {
    deserialize_sk(TEST_V1_SK)
}
pub fn v1_vk_deserialized() -> VerifyingKey {
    deserialize_vk(TEST_V1_VK)
}
pub fn v2_sk_deserialized() -> SigningKey {
    deserialize_sk(TEST_V2_SK)
}
pub fn v2_vk_deserialized() -> VerifyingKey {
    deserialize_vk(TEST_V2_VK)
}
pub fn v3_sk_deserialized() -> SigningKey {
    deserialize_sk(TEST_V3_SK)
}
pub fn v3_vk_deserialized() -> VerifyingKey {
    deserialize_vk(TEST_V3_VK)
}
pub fn v4_sk_deserialized() -> SigningKey {
    deserialize_sk(TEST_V4_SK)
}
pub fn v4_vk_deserialized() -> VerifyingKey {
    deserialize_vk(TEST_V4_VK)
}
