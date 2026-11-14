//! In-process network tests: 4 validators (+ a full node) talking HTTP on localhost.
use diseq_consensus::{
    fixtures::{default_validator_set, test_signing_keys},
    timeouts::Timing,
    types::{Block, Hash, Message},
    validators::FixedValidatorSet,
    ConsensusConfig, ConsensusStore,
};
use diseq_node::{
    config::NodeConfig,
    dissemination::BatchConfig,
    runtime::{spawn_node, NodeHandle},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

struct Net {
    _dir: TempDir,
    validator_addrs: Vec<String>,
    full_node_addr: String,
    genesis: u32,
}

fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

impl Net {
    fn new(base_port: u16) -> Self {
        Net {
            _dir: tempfile::tempdir().unwrap(),
            validator_addrs: (0..4)
                .map(|i| format!("127.0.0.1:{}", base_port + i))
                .collect(),
            full_node_addr: format!("127.0.0.1:{}", base_port + 4),
            genesis: now_secs(),
        }
    }

    fn config(&self, name: &str, addr: &str) -> NodeConfig {
        NodeConfig {
            db_path: self._dir.path().join(name).to_str().unwrap().into(),
            listen_addr: addr.into(),
            consensus: ConsensusConfig {
                timing: Timing {
                    propose_timeout_ms: 300,
                    prevote_timeout_ms: 300,
                    precommit_timeout_ms: 300,
                    timeout_delta_ms: 200,
                    rebroadcast_interval_ms: 500,
                    max_clock_drift: 1,
                },
                genesis_timestamp: self.genesis,
                max_block_messages: 10_000,
                max_block_batches: 100,
                expected_proposers: None,
                allow_empty_blocks: false,
                max_pending_batches: 1_000,
            },
            batches: BatchConfig {
                max_batch_messages: 100,
                batch_interval_ms: 20,
                max_message_bytes: 1_024,
                max_pending_messages: 10_000,
                max_inflight_batches: 64,
                retry_interval_ms: 300,
            },
            tick_interval_ms: 10,
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
            Some(sk),
        )
        .await
        .unwrap()
    }

    /// A non-validator node: it forwards client messages to the validators.
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
        timestamp: now_secs(),
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

fn sequenced_everywhere(nodes: &[&NodeHandle], messages: &[&Message]) -> bool {
    let ids: Vec<Hash> = messages.iter().map(|m| m.id()).collect();
    nodes
        .iter()
        .all(|n| n.db.sequenced(&ids).unwrap().into_iter().all(|s| s))
}

async fn wait_for(nodes: &[&NodeHandle], messages: &[&Message], timeout: Duration) {
    let start = Instant::now();
    while !sequenced_everywhere(nodes, messages) {
        assert!(
            start.elapsed() < timeout,
            "messages were not sequenced in time"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// All nodes must hold identical chains and identical message sequences (up to the
/// shortest one). Returns (block, messages) of the first node.
fn assert_same_chain(nodes: &[&NodeHandle]) -> Vec<(Block, Vec<Message>)> {
    let chains: Vec<Vec<(Block, Vec<Message>)>> = nodes
        .iter()
        .map(|n| {
            let height = n.db.sequenced_height().unwrap();
            (1..=height)
                .map(|h| {
                    let block = n.chain.block(h).unwrap().unwrap();
                    let digests: Vec<Hash> = block.batches.iter().map(|b| b.digest).collect();
                    let messages = n.db.output(h, &digests).unwrap().unwrap();
                    (block, messages)
                })
                .collect()
        })
        .collect();
    let min = chains.iter().map(|c| c.len()).min().unwrap();
    for chain in &chains[1..] {
        for h in 0..min {
            assert_eq!(
                chain[h].0.hash(),
                chains[0][h].0.hash(),
                "fork at height {}",
                h + 1
            );
            assert_eq!(
                chain[h].1,
                chains[0][h].1,
                "different sequence at height {}",
                h + 1
            );
        }
    }
    chains.into_iter().next().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn messages_from_any_node_are_sequenced_exactly_once() {
    let net = Net::new(27810);
    let mut v = Vec::new();
    for i in 0..4 {
        v.push(net.validator(i).await);
    }
    let full = net.full_node().await;

    let a = msg(b"to validator 0");
    let b = msg(b"to validator 2");
    let c = msg(b"to the full node");
    let d = msg(b"to two validators at once");
    assert!(schedule(&net.validator_addrs[0], &a)
        .await
        .starts_with("[Ok] Message is being sequenced"));
    assert!(schedule(&net.validator_addrs[2], &b)
        .await
        .starts_with("[Ok]"));
    assert!(schedule(&net.full_node_addr, &c).await.starts_with("[Ok]"));
    // the same message lands in two batches; the sequencer keeps the first occurrence
    assert!(schedule(&net.validator_addrs[1], &d)
        .await
        .starts_with("[Ok]"));
    assert!(schedule(&net.validator_addrs[3], &d)
        .await
        .starts_with("[Ok]"));

    let all: Vec<&NodeHandle> = v.iter().chain(std::iter::once(&full)).collect();
    wait_for(&all, &[&a, &b, &c, &d], Duration::from_secs(60)).await;
    let chain = assert_same_chain(&all);

    for m in [&a, &b, &c, &d] {
        let count: usize = chain
            .iter()
            .map(|(_, msgs)| msgs.iter().filter(|x| x == &m).count())
            .sum();
        assert_eq!(count, 1, "message sequenced {count} times");
    }
    for (block, _) in &chain {
        assert!(
            block.votes.len() >= 3,
            "block must carry a quorum certificate"
        );
        assert!(
            block.batches.iter().all(|c| c.attestations.len() >= 3),
            "batches must carry availability certificates"
        );
    }
    // resubmitting a sequenced message is a no-op
    assert!(schedule(&net.validator_addrs[1], &a)
        .await
        .starts_with("[Ok] Message already known"));

    // merkle membership proof from node 1 against its state root
    let latest = v[1].db.sequenced_height().unwrap();
    let start = Instant::now();
    let root = loop {
        let (root, height) = v[1].trie.root().await.unwrap();
        if height >= latest {
            break root;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "trie did not catch up"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let id = b.id();
    let proof = v[1]
        .trie
        .proof(id)
        .await
        .unwrap()
        .expect("b is in the trie");
    assert!(ciphercurve_trie::verify(&root, &id, &id, &proof));
    assert!(!ciphercurve_trie::verify(&root, &a.id(), &a.id(), &proof));
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

    // validator 3 joins late: it syncs certified blocks and fetches their batches
    let v3 = net.validator(3).await;
    let b = msg(b"after validator 3 joined");
    schedule(&net.validator_addrs[3], &b).await;
    wait_for(&[&v0, &v1, &v2, &v3], &[&a, &b], Duration::from_secs(60)).await;
    assert_same_chain(&[&v0, &v1, &v2, &v3]);
}
