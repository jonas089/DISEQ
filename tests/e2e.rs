//! In-process network tests: real HTTP gossip on localhost, fast rounds.
use ciphercurve_trie::merkle::{verify_merkle_proof, MerkleProof};
use l2_sequencer::{
    config::{consensus::default_validator_set, consensus::test_signing_keys, node::NodeConfig},
    consensus::{logic::Timing, validators::FixedValidatorSet},
    get_current_time,
    node::LocalValidator,
    runtime::{spawn_node, NodeHandle},
    types::{id_to_trie_key, Block, Message},
};
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct Net {
    _dir: TempDir,
    validator_addrs: Vec<String>,
    full_node_addr: String,
    genesis: u32,
}

impl Net {
    fn new(base_port: u16) -> Self {
        Net {
            _dir: tempfile::tempdir().unwrap(),
            validator_addrs: (0..4)
                .map(|i| format!("127.0.0.1:{}", base_port + i))
                .collect(),
            full_node_addr: format!("127.0.0.1:{}", base_port + 4),
            genesis: get_current_time(),
        }
    }

    fn config(&self, name: &str, addr: &str) -> NodeConfig {
        NodeConfig {
            db_path: self
                ._dir
                .path()
                .join(format!("{name}.sqlite"))
                .to_str()
                .unwrap()
                .into(),
            listen_addr: addr.into(),
            timing: Timing {
                propose_timeout_ms: 600,
                prevote_timeout_ms: 300,
                precommit_timeout_ms: 300,
                timeout_delta_ms: 200,
                rebroadcast_interval_ms: 500,
                max_clock_drift: 1,
            },
            genesis_timestamp: self.genesis,
            max_block_messages: 1_000,
            max_pool_size: 10_000,
            max_message_bytes: 1_024,
            expected_proposers: None,
            allow_empty_blocks: false,
            tick_interval_ms: 100,
            sync_interval_ms: 500,
            extra_peers: vec![self.full_node_addr.clone()],
        }
    }

    async fn validator(&self, i: usize) -> NodeHandle {
        let sk = test_signing_keys().into_iter().nth(i).unwrap();
        spawn_node(
            self.config(&format!("v{i}"), &self.validator_addrs[i]),
            Box::new(FixedValidatorSet(default_validator_set(
                &self.validator_addrs,
            ))),
            Some(LocalValidator::from_signing_key(sk)),
        )
        .await
        .unwrap()
    }

    /// A non-validator node: it can only get its messages sequenced through mempool sync.
    async fn full_node(&self) -> NodeHandle {
        let mut config = self.config("full", &self.full_node_addr);
        config.extra_peers.clear();
        spawn_node(
            config,
            Box::new(FixedValidatorSet(default_validator_set(
                &self.validator_addrs,
            ))),
            None,
        )
        .await
        .unwrap()
    }
}

fn msg(data: &[u8]) -> Message {
    Message {
        data: data.to_vec(),
        timestamp: get_current_time(),
    }
}

async fn schedule(addr: &str, message: &Message) -> String {
    reqwest::Client::new()
        .post(format!("http://{addr}/schedule"))
        .json(message)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

async fn committed_everywhere(nodes: &[&NodeHandle], messages: &[&Message]) -> bool {
    for node in nodes {
        let node = node.node.lock().await;
        for m in messages {
            if !node.store.is_committed(&m.id()).unwrap() {
                return false;
            }
        }
    }
    true
}

async fn wait_for(nodes: &[&NodeHandle], messages: &[&Message], timeout: Duration) {
    let start = Instant::now();
    while !committed_everywhere(nodes, messages).await {
        assert!(
            start.elapsed() < timeout,
            "messages were not sequenced in time"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// All nodes must hold identical chains (up to the shortest one).
async fn assert_same_chain(nodes: &[&NodeHandle]) -> Vec<Block> {
    let mut chains = Vec::new();
    for node in nodes {
        let node = node.node.lock().await;
        let height = node.store.latest_height().unwrap();
        chains.push(
            (0..=height)
                .map(|h| node.store.block(h).unwrap().unwrap())
                .collect::<Vec<_>>(),
        );
    }
    let min = chains.iter().map(|c| c.len()).min().unwrap();
    for chain in &chains[1..] {
        for h in 0..min {
            assert_eq!(chain[h].hash(), chains[0][h].hash(), "fork at height {h}");
        }
    }
    chains.swap_remove(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn messages_from_any_node_are_sequenced_by_whichever_validator_wins() {
    let net = Net::new(27810);
    let v: Vec<NodeHandle> = futures_join(&net).await;
    let full = net.full_node().await;

    // submitted to a validator, to another validator, and to a non-validator via HTTP
    let a = msg(b"to validator 0");
    let b = msg(b"to validator 2");
    let c = msg(b"to the full node");
    assert!(schedule(&net.validator_addrs[0], &a)
        .await
        .starts_with("[Ok] Message is being sequenced"));
    assert!(schedule(&net.validator_addrs[2], &b)
        .await
        .starts_with("[Ok]"));
    assert!(schedule(&net.full_node_addr, &c).await.starts_with("[Ok]"));
    // and one inserted locally without any gossip: only mempool anti-entropy can spread it
    let d = msg(b"no gossip, only anti-entropy");
    full.node.lock().await.submit_message(&d).unwrap();

    let all: Vec<&NodeHandle> = v.iter().chain(std::iter::once(&full)).collect();
    wait_for(&all, &[&a, &b, &c, &d], Duration::from_secs(60)).await;
    let chain = assert_same_chain(&all).await;

    // c and d never entered a validator through /schedule; a validator still sequenced them
    for m in [&c, &d] {
        let block = chain.iter().find(|b| b.messages.contains(m)).unwrap();
        assert!(!block.proposer.is_empty());
        assert!(
            block.votes.len() >= 3,
            "block must carry a quorum certificate"
        );
    }
    // each message exactly once
    for m in [&a, &b, &c, &d] {
        assert_eq!(chain.iter().filter(|b| b.messages.contains(m)).count(), 1);
    }
    // nothing left in any pool
    for node in &all {
        assert!(node.node.lock().await.store.pool_ids().unwrap().is_empty());
    }
    // resubmitting a sequenced message is a no-op
    assert!(schedule(&net.validator_addrs[1], &a)
        .await
        .starts_with("[Ok] Message already known"));

    // merkle inclusion proof from node 1 against its state root
    let mut node = v[1].node.lock().await;
    let root = node.trie_root().hash.clone().unwrap();
    let proof: MerkleProof = node.merkle_proof(id_to_trie_key(&b.id())).unwrap();
    verify_merkle_proof(proof.nodes, root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn progresses_with_one_validator_down_and_late_validator_catches_up() {
    let net = Net::new(27830);
    let v0 = net.validator(0).await;
    let v1 = net.validator(1).await;
    let v2 = net.validator(2).await;

    let a = msg(b"while validator 3 is offline");
    schedule(&net.validator_addrs[1], &a).await;
    wait_for(&[&v0, &v1, &v2], &[&a], Duration::from_secs(60)).await;

    // validator 3 joins late and must sync the certified chain
    let v3 = net.validator(3).await;
    let b = msg(b"after validator 3 joined");
    schedule(&net.validator_addrs[3], &b).await;
    wait_for(&[&v0, &v1, &v2, &v3], &[&a, &b], Duration::from_secs(60)).await;
    assert_same_chain(&[&v0, &v1, &v2, &v3]).await;
}

async fn futures_join(net: &Net) -> Vec<NodeHandle> {
    let mut nodes = Vec::new();
    for i in 0..4 {
        nodes.push(net.validator(i).await);
    }
    nodes
}
