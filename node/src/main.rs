use colored::Colorize;
use diseq_consensus::{
    fixtures::{default_validator_set, test_signing_keys},
    validators::FixedValidatorSet,
};
use diseq_node::{
    config::NodeConfig, initial_print, network::peers::DEFAULT_PEERS, runtime::spawn_node,
};
use std::env;

#[tokio::main]
async fn main() {
    initial_print();
    let config = NodeConfig::from_env();

    // Default: the fixed 4 validator test set. Other rule sets (e.g. PoS) plug in by
    // passing a different `ValidatorSetPolicy` to `spawn_node`.
    let addresses: Vec<String> = match env::var("PEERS") {
        Ok(peers) => peers.split(',').map(str::to_string).collect(),
        Err(_) => DEFAULT_PEERS.iter().map(|p| p.to_string()).collect(),
    };
    let policy = Box::new(FixedValidatorSet(default_validator_set(&addresses)));

    // LOCAL_VALIDATOR=0..3 selects a test key; LOCAL_VALIDATOR=none runs a full node.
    let signing_key = match env::var("LOCAL_VALIDATOR").as_deref() {
        Ok("none") => None,
        other => {
            let index: usize = other
                .unwrap_or("0")
                .parse()
                .expect("LOCAL_VALIDATOR: 0-3 or none");
            Some(
                test_signing_keys()
                    .into_iter()
                    .nth(index)
                    .expect("LOCAL_VALIDATOR out of range"),
            )
        }
    };

    println!(
        "{}{}",
        "Starting Node: ".green().italic(),
        config.listen_addr.yellow().bold()
    );
    let handle = spawn_node(config, policy, signing_key)
        .await
        .expect("failed to start node");
    handle.wait().await;
}
