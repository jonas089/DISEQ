#[cfg(test)]
mod tests {
    #[test]
    fn generate_zk_random_number_risc0() {
        use prover::generate_random_number;
        use zk_logic::types::CircuitOutputs;
        let random_number_receipt = generate_random_number(vec![0; 32], vec![0; 32]);
        let outputs: CircuitOutputs = random_number_receipt.journal.decode().unwrap();
        println!("Outputs: {:?}", &outputs);
    }
}
