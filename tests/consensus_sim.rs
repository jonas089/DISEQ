//! Deterministic adversarial simulation of the consensus state machine.
//!
//! Three honest nodes and one Byzantine validator (25% of the weight, the maximum a 4 node
//! network tolerates). The network drops, delays and reorders messages until a global
//! stabilization time (GST), after which delivery is reliable and fast. The Byzantine
//! validator equivocates on everything: it sends different proposals and different
//! prevotes/precommits to every honest node, in every round it observes.
//!
//! Safety: honest nodes never commit different blocks at the same height (checked for every
//! seed, before and after GST). Liveness: after GST every honest node keeps committing.
use l2_sequencer::{
    config::{
        consensus::{default_validator_set, test_signing_keys},
        node::NodeConfig,
    },
    consensus::{
        election::{block_randomness, vrf_input},
        logic::Timing,
        validators::FixedValidatorSet,
    },
    node::{LocalValidator, Node, Outgoing},
    types::{Block, Hash, Message, Proposal, Vote, VoteKind},
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::{BTreeMap, HashMap};

const HONEST: [usize; 3] = [0, 1, 3];
const BYZANTINE: usize = 2;
const GENESIS: u32 = 1_700_000_000;
const STEP_MS: u64 = 50;
const GST_MS: u64 = 15_000;
const END_MS: u64 = 40_000;

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
enum Msg {
    Proposal(Proposal),
    Vote(Vote),
}

struct Sim {
    _dir: tempfile::TempDir,
    nodes: BTreeMap<usize, Node>,
    byz: LocalValidator,
    rng: StdRng,
    now: u64,
    /// (deliver_at, recipient, message)
    queue: Vec<(u64, usize, Msg)>,
    /// block hashes seen on the network per height, for Byzantine votes
    known_blocks: HashMap<u32, Vec<Hash>>,
    byz_counter: u64,
}

fn config(dir: &tempfile::TempDir, i: usize) -> NodeConfig {
    NodeConfig {
        db_path: dir
            .path()
            .join(format!("n{i}.sqlite"))
            .to_str()
            .unwrap()
            .into(),
        listen_addr: format!("node-{i}"),
        timing: Timing {
            propose_timeout_ms: 1_000,
            prevote_timeout_ms: 500,
            precommit_timeout_ms: 500,
            timeout_delta_ms: 250,
            rebroadcast_interval_ms: 1_000,
            max_clock_drift: 2,
        },
        genesis_timestamp: GENESIS,
        max_block_messages: 100,
        max_pool_size: 10_000,
        max_message_bytes: 1_024,
        expected_proposers: None,
        allow_empty_blocks: false,
        tick_interval_ms: STEP_MS,
        sync_interval_ms: 500,
        extra_peers: vec![],
    }
}

impl Sim {
    fn new(seed: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let addrs: Vec<String> = (0..4).map(|i| format!("node-{i}")).collect();
        let keys = test_signing_keys();
        let mut nodes = BTreeMap::new();
        for i in HONEST {
            let node = Node::new(
                config(&dir, i),
                Box::new(FixedValidatorSet(default_validator_set(&addrs))),
                Some(LocalValidator::from_signing_key(keys[i].clone())),
            )
            .unwrap();
            nodes.insert(i, node);
        }
        Sim {
            _dir: dir,
            nodes,
            byz: LocalValidator::from_signing_key(keys[BYZANTINE].clone()),
            rng: StdRng::seed_from_u64(seed),
            now: GENESIS as u64 * 1000,
            queue: Vec::new(),
            known_blocks: HashMap::new(),
            byz_counter: 0,
        }
    }

    fn elapsed(&self) -> u64 {
        self.now - GENESIS as u64 * 1000
    }

    /// Before GST: 30% loss, up to 3s delay (reordering). After: no loss, <= 100ms delay.
    fn send(&mut self, to: usize, msg: Msg) {
        let (drop, max_delay) = if self.elapsed() < GST_MS {
            (0.3, 3_000)
        } else {
            (0.0, 100)
        };
        if self.rng.gen_bool(drop) {
            return;
        }
        let at = self.now + self.rng.gen_range(0..=max_delay);
        self.queue.push((at, to, msg));
    }

    fn broadcast(&mut self, from: usize, outgoing: Vec<Outgoing>) {
        for item in outgoing {
            let msg = match item {
                Outgoing::Proposal(p) => {
                    self.known_blocks
                        .entry(p.height)
                        .or_default()
                        .push(p.block.hash());
                    Msg::Proposal(p)
                }
                Outgoing::Vote(v) => Msg::Vote(v),
            };
            for to in HONEST {
                if to != from {
                    self.send(to, msg.clone());
                }
            }
        }
    }

    fn deliver_due(&mut self) {
        let now = self.now;
        let (due, rest): (Vec<_>, Vec<_>) = self.queue.drain(..).partition(|(at, _, _)| *at <= now);
        self.queue = rest;
        for (_, to, msg) in due {
            let node = self.nodes.get_mut(&to).unwrap();
            let result = match msg.clone() {
                Msg::Proposal(p) => node.on_proposal(p, now),
                Msg::Vote(v) => node.on_vote(v, now),
            };
            // honest nodes relay what is new to them, like the HTTP gossip does
            if let Ok((received, outgoing)) = result {
                if received == l2_sequencer::node::Received::New {
                    for other in HONEST {
                        if other != to {
                            self.send(other, msg.clone());
                        }
                    }
                }
                self.broadcast(to, outgoing);
            }
        }
    }

    /// The Byzantine validator sends every honest node its own conflicting view.
    fn byzantine_step(&mut self) {
        if !self.rng.gen_bool(0.3) {
            return;
        }
        for to in HONEST {
            let (height, round, _) = self.nodes[&to].consensus_position();
            let parent = self.nodes[&to].store.latest_block().unwrap();
            // a fresh, conflicting proposal per recipient
            self.byz_counter += 1;
            let input = vrf_input(&block_randomness(&parent), height, round);
            let (_, claim) = self.byz.vrf.prove(&input);
            let mut block = Block {
                height,
                round,
                parent_hash: parent.hash(),
                proposer: self.byz.id(),
                vrf: Some(claim.clone()),
                messages: vec![Message {
                    data: format!("byzantine-{}", self.byz_counter).into_bytes(),
                    timestamp: 0,
                }],
                timestamp: (self.now / 1000) as u32,
                signature: None,
                votes: vec![],
            };
            block.signature = Some(self.byz.sign(&Block::signing_payload(&block.hash())));
            let hash = block.hash();
            self.known_blocks.entry(height).or_default().push(hash);
            let proposal = Proposal {
                height,
                round,
                valid_round: None,
                proposer: self.byz.id(),
                vrf: claim,
                signature: self
                    .byz
                    .sign(&Proposal::signing_payload(height, round, None, &hash)),
                block,
            };
            self.send(to, Msg::Proposal(proposal));
            // conflicting votes for a random known block (or nil), per recipient and round
            for kind in [VoteKind::Prevote, VoteKind::Precommit] {
                let choices = self.known_blocks.get(&height).cloned().unwrap_or_default();
                let target = if choices.is_empty() || self.rng.gen_bool(0.2) {
                    None
                } else {
                    Some(choices[self.rng.gen_range(0..choices.len())])
                };
                let vote_round = round + self.rng.gen_range(0..=1);
                let vote = Vote {
                    kind,
                    height,
                    round: vote_round,
                    block_hash: target,
                    validator: self.byz.id(),
                    signature: self
                        .byz
                        .sign(&Vote::signing_payload(kind, height, vote_round, &target)),
                };
                self.send(to, Msg::Vote(vote));
            }
        }
    }

    /// Lagging nodes fetch certified blocks from nodes that are ahead (like the sync loop).
    fn sync(&mut self) {
        for to in HONEST {
            for from in HONEST {
                let next = self.nodes[&to].store.latest_height().unwrap() + 1;
                if let Some(block) = self.nodes[&from].store.block(next).unwrap() {
                    self.nodes
                        .get_mut(&to)
                        .unwrap()
                        .on_certified_block(block)
                        .unwrap();
                }
            }
        }
    }

    fn assert_safety(&self) {
        let mut committed: HashMap<u32, Hash> = HashMap::new();
        for (i, node) in &self.nodes {
            for h in 1..=node.store.latest_height().unwrap() {
                let hash = node.store.block(h).unwrap().unwrap().hash();
                let first = *committed.entry(h).or_insert(hash);
                assert_eq!(first, hash, "SAFETY VIOLATION at height {h} (node {i})");
            }
        }
    }

    fn run(&mut self) -> Vec<u32> {
        let mut tx = 0u64;
        let mut heights_at_gst = Vec::new();
        while self.elapsed() < END_MS {
            // steady stream of client messages, submitted to random honest nodes
            if self.elapsed().is_multiple_of(1_000) {
                tx += 1;
                let to = HONEST[self.rng.gen_range(0..HONEST.len())];
                let msg = Message {
                    data: format!("tx-{tx}").into_bytes(),
                    timestamp: 0,
                };
                for i in HONEST {
                    // mempool gossip is lossy before GST too
                    if i == to || self.rng.gen_bool(0.7) {
                        let _ = self.nodes.get_mut(&i).unwrap().submit_message(&msg);
                    }
                }
            }
            for i in HONEST {
                let out = self.nodes.get_mut(&i).unwrap().on_tick(self.now).unwrap();
                self.broadcast(i, out);
            }
            self.byzantine_step();
            self.deliver_due();
            if self.elapsed().is_multiple_of(500) {
                self.sync();
            }
            self.assert_safety();
            if self.elapsed() == GST_MS {
                heights_at_gst = HONEST
                    .iter()
                    .map(|i| self.nodes[i].store.latest_height().unwrap())
                    .collect();
            }
            self.now += STEP_MS;
        }
        let final_heights: Vec<u32> = HONEST
            .iter()
            .map(|i| self.nodes[i].store.latest_height().unwrap())
            .collect();
        if std::env::var("SIM_DEBUG").is_ok() {
            for i in HONEST {
                let n = &self.nodes[&i];
                eprintln!(
                    "node {i}: pool {} {}",
                    n.store.pool_ids().unwrap().len(),
                    n.debug_state()
                );
            }
        }
        for (before, after) in heights_at_gst.iter().zip(&final_heights) {
            assert!(
                after >= &(before + 5),
                "no liveness after GST: heights {heights_at_gst:?} -> {final_heights:?}"
            );
        }
        final_heights
    }
}

#[test]
fn safe_and_live_under_equivocating_byzantine_validator_and_lossy_network() {
    let seeds: u64 = std::env::var("SIM_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let start: u64 = std::env::var("SIM_SEED_START")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    for seed in start..start + seeds {
        let heights = Sim::new(seed).run();
        println!("seed {seed}: final heights {heights:?}");
    }
}

/// A validator locked on block X must not prevote for a conflicting block Y in a later
/// round, even if Y claims a valid round, unless Y really had a 2/3+ prevote quorum.
#[test]
fn locked_validator_refuses_conflicting_block() {
    let mut sim = Sim::new(99);
    let t0 = sim.now;
    // node 0 proposes X in round 0
    sim.nodes
        .get_mut(&0)
        .unwrap()
        .submit_message(&Message {
            data: b"x".to_vec(),
            timestamp: 0,
        })
        .unwrap();
    let out = sim.nodes.get_mut(&0).unwrap().on_tick(t0).unwrap();
    let Outgoing::Proposal(px) = &out[0] else {
        panic!("expected proposal")
    };
    let x = px.block.hash();
    // node 1 receives X; after the propose timeout it prevotes X
    let b = sim.nodes.get_mut(&1).unwrap();
    b.on_tick(t0).unwrap();
    b.on_proposal(px.clone(), t0).unwrap();
    let t1 = t0 + 1_000;
    let out = b.on_tick(t1).unwrap();
    assert_eq!(own_vote(&out, VoteKind::Prevote, 0), Some(Some(x)));
    // prevotes from node 0 and the Byzantine node complete a polka: node 1 locks on X
    let vote = |signer: &LocalValidator, kind, round, hash: Option<Hash>| Vote {
        kind,
        height: 1,
        round,
        block_hash: hash,
        validator: signer.id(),
        signature: signer.sign(&Vote::signing_payload(kind, 1, round, &hash)),
    };
    let a_key = LocalValidator::from_signing_key(test_signing_keys()[0].clone());
    let (_, out) = b
        .on_vote(vote(&a_key, VoteKind::Prevote, 0, Some(x)), t1)
        .unwrap();
    assert_eq!(own_vote(&out, VoteKind::Precommit, 0), None);
    let (_, out) = b
        .on_vote(vote(&sim.byz, VoteKind::Prevote, 0, Some(x)), t1)
        .unwrap();
    assert_eq!(own_vote(&out, VoteKind::Precommit, 0), Some(Some(x)));

    // a restart must not forget the lock or the precommit (no double signing)
    assert_eq!(b.locked(), Some((0, x)));
    let restarted = Node::new(
        config(&sim._dir, 1),
        Box::new(FixedValidatorSet(default_validator_set(
            &(0..4).map(|i| format!("node-{i}")).collect::<Vec<_>>(),
        ))),
        Some(LocalValidator::from_signing_key(
            test_signing_keys()[1].clone(),
        )),
    )
    .unwrap();
    assert_eq!(restarted.locked(), Some((0, x)));
    assert!(restarted.debug_state().contains("(Precommit, 0)"));
    drop(restarted);

    // move node 1 to round 1 with nil precommits from others (no commit happened)
    b.on_vote(vote(&a_key, VoteKind::Precommit, 0, None), t1)
        .unwrap();
    b.on_vote(vote(&sim.byz, VoteKind::Precommit, 0, None), t1)
        .unwrap();
    let t2 = t1 + 600;
    b.on_tick(t2).unwrap();
    assert_eq!(b.consensus_position().1, 1, "node 1 should be in round 1");

    // the Byzantine node proposes Y in round 1, falsely claiming valid round 0
    let parent = b.store.latest_block().unwrap();
    let input = vrf_input(&block_randomness(&parent), 1, 1);
    let (_, claim) = sim.byz.vrf.prove(&input);
    let mut y = Block {
        height: 1,
        round: 1,
        parent_hash: parent.hash(),
        proposer: sim.byz.id(),
        vrf: Some(claim.clone()),
        messages: vec![Message {
            data: b"y".to_vec(),
            timestamp: 0,
        }],
        timestamp: (t2 / 1000) as u32,
        signature: None,
        votes: vec![],
    };
    y.signature = Some(sim.byz.sign(&Block::signing_payload(&y.hash())));
    let yh = y.hash();
    for valid_round in [None, Some(0)] {
        let p = Proposal {
            height: 1,
            round: 1,
            valid_round,
            proposer: sim.byz.id(),
            vrf: claim.clone(),
            signature: sim
                .byz
                .sign(&Proposal::signing_payload(1, 1, valid_round, &yh)),
            block: y.clone(),
        };
        // the second one is an equivocation and is rejected; either way Y gets no prevote
        let _ = b.on_proposal(p, t2);
    }
    let out = b.on_tick(t2 + 2_000).unwrap();
    let prevote = own_vote(&out, VoteKind::Prevote, 1).expect("node 1 prevotes in round 1");
    assert_ne!(
        prevote,
        Some(yh),
        "locked node prevoted a conflicting block"
    );
    // it re-proposed and prevoted its locked block instead
    assert_eq!(prevote, Some(x));
}

/// The value of the node's own vote of `kind` in `round` among its outgoing messages.
fn own_vote(out: &[Outgoing], kind: VoteKind, round: u64) -> Option<Option<Hash>> {
    let own = LocalValidator::from_signing_key(test_signing_keys()[1].clone()).id();
    out.iter().find_map(|o| match o {
        Outgoing::Vote(v) if v.kind == kind && v.round == round && v.validator == own => {
            Some(v.block_hash)
        }
        _ => None,
    })
}
