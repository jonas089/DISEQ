use prover::ZK_RAND_ID;
use risc0_zkvm::Receipt;
use zk_logic::random_bytes_to_int;
use zk_logic::types::CircuitOutputs;
#[allow(unused)]
pub fn verify_random_number(receipt: Receipt) -> u32 {
    receipt.verify(ZK_RAND_ID).expect("Invalid Random Number");
    let outputs: CircuitOutputs = receipt.journal.decode().unwrap();
    *random_bytes_to_int(&outputs.random_bytes)
        .to_u32_digits()
        .1
        .last()
        .unwrap()
}
#[test]
fn test_verify_random_number() {
    use prover::generate_random_number;
    let random_number: Receipt = generate_random_number(vec![0; 32], vec![0; 32]);
    let result = verify_random_number(random_number);
    println!("Random u32: {:?}", &result);
}
