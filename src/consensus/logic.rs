use crate::types::ConsensusCommitment;
use crate::{config::consensus::ROUND_DURATION, get_current_time};
use k256::ecdsa::VerifyingKey;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use zk_logic::{random_bytes_to_int, types::CircuitOutputs};
pub fn evaluate_commitment(
    commitment: ConsensusCommitment,
    validators: Vec<VerifyingKey>,
) -> VerifyingKey {
    let circuit_outputs: CircuitOutputs = commitment.receipt.journal.decode().unwrap();
    choose_winner(
        random_bytes_to_int(&circuit_outputs.random_bytes),
        validators,
    )
}
pub fn get_committing_validator(
    last_block_unix_timestamp: u32,
    validators: Vec<VerifyingKey>,
) -> VerifyingKey {
    let round = current_round(last_block_unix_timestamp) - 1;
    // returns the current validator
    validators[round as usize % (validators.len() - 1)]
}
fn choose_winner(random_commitment: BigInt, validators: Vec<VerifyingKey>) -> VerifyingKey {
    let index = (random_commitment % (validators.len() - 1))
        .to_u32()
        .unwrap();
    validators[index as usize]
}
pub fn current_round(last_block_unix_timestamp: u32) -> u32 {
    (get_current_time() - last_block_unix_timestamp) / (ROUND_DURATION) + 1
}
