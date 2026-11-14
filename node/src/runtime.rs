//! Wires the protocol to the network: the single writer, and node startup.
//!
//! **Single writer.** One thread owns all mutable protocol state ([`Core`]: the consensus
//! state machine and batch dissemination) and is the only code that changes it. Everything
//! else talks to it over two bounded channels:
//!
//! * `input`: consensus traffic (proposals, votes, attestations, certificates), synced
//!   blocks and queries. Always drained first, so consensus never queues behind data.
//! * `data`: batches from peers and client messages. Drained in bulk.
//!
//! HTTP handlers decode requests and hash messages on the async runtime, in parallel, before
//! anything reaches the writer. Committed blocks go to the [`Sequencer`] task, which resolves
//! payloads off the consensus path and feeds the Merkle trie thread.
//!
//! ```text
//!  HTTP ─► input/data channels ─► writer (Consensus + Dissemination) ─► peers
//!                                        │ committed blocks
//!                                        ▼
//!                                   Sequencer ─► message index, outputs ─► trie writer
//! ```
use crate::api::{router, AppState};
use crate::config::NodeConfig;
use crate::dissemination::{Dissemination, Retry};
use crate::network::{sync::sync_blocks, transport::Net, wire, DataMsg, PeerMsg};
use crate::sequencer::Sequencer;
use crate::storage::{chain::ChainStore, trie::TrieService, Db};
use crate::{log_warn, now_ms};
use anyhow::{anyhow, Result};
use diseq_consensus::types::{Batch, BatchCert, Block, Hash, Message};
use diseq_consensus::validators::ValidatorSetPolicy;
use diseq_consensus::{Consensus, LocalValidator, Outgoing, Received};
use serde::Serialize;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;

const INPUT_QUEUE: usize = 16_384;
const DATA_QUEUE: usize = 4_096;

/// All mutable protocol state; owned by the writer thread.
pub struct Core {
    pub consensus: Consensus<ChainStore>,
    pub dissemination: Dissemination,
}

type Query = Box<dyn FnOnce(&mut Core) + Send>;
pub type Verdicts = Vec<Result<Received, String>>;

pub enum Input {
    Peer(PeerMsg),
    Certified(Block, oneshot::Sender<Result<()>>),
    Query(Query),
}

pub enum DataInput {
    Batch(Batch),
    /// client messages with ids computed by [`Message::id`]
    Messages {
        messages: Vec<(Hash, Message)>,
        reply: Option<oneshot::Sender<Verdicts>>,
    },
}

/// Handle to the writer thread.
#[derive(Clone)]
pub struct Writer {
    input: mpsc::Sender<Input>,
    data: mpsc::Sender<DataInput>,
}

impl Writer {
    pub async fn send(&self, input: Input) -> Result<()> {
        self.input
            .send(input)
            .await
            .map_err(|_| anyhow!("node stopped"))
    }

    /// Runs `f` on the writer thread and returns its result.
    pub async fn query<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Core) -> R + Send + 'static,
    ) -> Result<R> {
        let (tx, rx) = oneshot::channel();
        self.send(Input::Query(Box::new(move |core| {
            let _ = tx.send(f(core));
        })))
        .await?;
        Ok(rx.await?)
    }

    pub async fn certify(&self, block: Block) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(Input::Certified(block, tx)).await?;
        rx.await?
    }

    /// Queues data without waiting; fails if the node is overloaded.
    pub fn try_data(&self, input: DataInput) -> Result<()> {
        self.data
            .try_send(input)
            .map_err(|_| anyhow!("node is overloaded, retry later"))
    }

    /// Submits client messages and waits for the per-message verdicts.
    pub async fn submit(&self, messages: Vec<(Hash, Message)>) -> Result<Verdicts> {
        let (tx, rx) = oneshot::channel();
        self.try_data(DataInput::Messages {
            messages,
            reply: Some(tx),
        })?;
        Ok(rx.await?)
    }
}

pub struct NodeHandle {
    pub writer: Writer,
    pub db: Arc<Db>,
    pub chain: ChainStore,
    pub trie: TrieService,
    pub tasks: Vec<JoinHandle<()>>,
}

impl NodeHandle {
    /// Runs until one of the node's tasks exits, then stops the others.
    pub async fn wait(mut self) {
        let tasks = std::mem::take(&mut self.tasks);
        let aborts: Vec<_> = tasks.iter().map(|t| t.abort_handle()).collect();
        let mut set = tokio::task::JoinSet::new();
        for task in tasks {
            set.spawn(task);
        }
        let _ = set.join_next().await;
        for abort in aborts {
            abort.abort();
        }
    }
}

impl Drop for NodeHandle {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

pub async fn spawn_node(
    config: NodeConfig,
    policy: Box<dyn ValidatorSetPolicy>,
    signing_key: Option<k256::ecdsa::SigningKey>,
) -> Result<NodeHandle> {
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    let db = Arc::new(Db::open(&config.db_path)?);
    let chain = ChainStore::new(db.clone());
    let identity = |sk: &k256::ecdsa::SigningKey| LocalValidator::from_signing_key(sk.clone());
    let consensus = Consensus::new(
        config.consensus.clone(),
        chain.clone(),
        policy,
        signing_key.as_ref().map(identity),
    )?;
    let dissemination = Dissemination::new(
        signing_key.as_ref().map(identity),
        db.clone(),
        config.batches.clone(),
        now_ms(),
    );
    let (trie, trie_height) = TrieService::start(db.clone())?;
    let net = Net::new(tokio::runtime::Handle::current());

    let (input_tx, input_rx) = mpsc::channel(INPUT_QUEUE);
    let (data_tx, data_rx) = mpsc::channel(DATA_QUEUE);
    let (committed_tx, committed_rx) = mpsc::unbounded_channel();
    let writer = Writer {
        input: input_tx,
        data: data_tx,
    };
    let fetch_peers = Arc::new(RwLock::new(Vec::new()));
    let links = Links {
        net: net.clone(),
        listen_addr: config.listen_addr.clone(),
        extra_peers: config.extra_peers.clone(),
        validators: Vec::new(),
        all: Vec::new(),
        committed: committed_tx,
        fetch_peers: fetch_peers.clone(),
    };
    let core = Core {
        consensus,
        dissemination,
    };
    let tick = Duration::from_millis(config.tick_interval_ms);
    std::thread::Builder::new()
        .name("consensus-writer".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("writer runtime");
            rt.block_on(run_writer(core, links, tick, input_rx, data_rx));
        })?;

    let sequencer = tokio::spawn(
        Sequencer {
            db: db.clone(),
            chain: chain.clone(),
            trie: trie.clone(),
            net: net.clone(),
            peers: fetch_peers.clone(),
        }
        .run(trie_height, committed_rx),
    );

    let state = AppState {
        writer: writer.clone(),
        db: db.clone(),
        chain: chain.clone(),
        trie: trie.clone(),
        max_message_bytes: config.batches.max_message_bytes,
    };
    let api = tokio::spawn({
        let app = router(state);
        async move {
            if let Err(e) = axum::serve(listener, app).await {
                log_warn(format!("API server stopped: {e}"));
            }
        }
    });

    let sync_interval = Duration::from_millis(config.sync_interval_ms);
    let sync = tokio::spawn({
        let (writer, chain, net) = (writer.clone(), chain.clone(), net.clone());
        async move {
            loop {
                tokio::time::sleep(sync_interval).await;
                let peers = fetch_peers.read().expect("peers lock").clone();
                if let Err(e) = sync_blocks(&writer, &chain, &net, &peers).await {
                    log_warn(format!("sync failed: {e:#}"));
                }
            }
        }
    });

    Ok(NodeHandle {
        writer,
        db,
        chain,
        trie,
        tasks: vec![api, sync, sequencer],
    })
}

/// Where the writer sends things.
struct Links {
    net: Net,
    listen_addr: String,
    extra_peers: Vec<String>,
    /// other validators of the current height
    validators: Vec<String>,
    /// other validators and extra (non-validator) peers
    all: Vec<String>,
    committed: mpsc::UnboundedSender<Block>,
    fetch_peers: Arc<RwLock<Vec<String>>>,
}

impl Links {
    fn refresh(&mut self, core: &Core) {
        let me = core.consensus.local_id();
        let mut validators: Vec<String> = core
            .consensus
            .current_validators()
            .iter()
            .filter(|v| Some(v.id_bytes()) != me && v.address != self.listen_addr)
            .map(|v| v.address.clone())
            .collect();
        validators.sort();
        validators.dedup();
        let mut all: Vec<String> = validators
            .iter()
            .chain(&self.extra_peers)
            .filter(|a| **a != self.listen_addr)
            .cloned()
            .collect();
        all.sort();
        all.dedup();
        *self.fetch_peers.write().expect("peers lock") = all.clone();
        self.validators = validators;
        self.all = all;
    }

    fn consensus_to(&self, peers: &[String], msg: &PeerMsg) {
        match wire::encode(msg) {
            Ok(bytes) => self.net.send_consensus(peers, bytes),
            Err(e) => log_warn(format!("failed to encode {msg:?}: {e:#}")),
        }
    }

    fn data_to(&self, peers: &[String], msg: &impl Serialize) {
        match wire::encode(msg) {
            Ok(bytes) => self.net.send_data(peers, bytes),
            Err(e) => log_warn(format!("failed to encode data: {e:#}")),
        }
    }

    fn outgoing(&self, out: Vec<Outgoing>) {
        for item in out {
            let msg = match item {
                Outgoing::Proposal(p) => PeerMsg::Proposal(p),
                Outgoing::Vote(v) => PeerMsg::Vote(v),
            };
            self.consensus_to(&self.all, &msg);
        }
    }
}

/// The writer loop: the only place protocol state is mutated.
async fn run_writer(
    mut core: Core,
    mut links: Links,
    tick: Duration,
    mut input_rx: mpsc::Receiver<Input>,
    mut data_rx: mpsc::Receiver<DataInput>,
) {
    links.refresh(&core);
    let mut height = core.consensus.position().0;
    let mut next_tick = Instant::now();
    let (mut inputs, mut data) = (Vec::new(), Vec::new());
    loop {
        tokio::select! {
            biased;
            n = input_rx.recv_many(&mut inputs, 1_024) => {
                if n == 0 {
                    break; // all handles dropped: the node is shutting down
                }
                for input in inputs.drain(..) {
                    handle_input(&mut core, &links, input);
                }
            }
            _ = tokio::time::sleep_until(next_tick) => {
                on_tick(&mut core, &links);
                next_tick = Instant::now() + tick;
            }
            n = data_rx.recv_many(&mut data, 256) => {
                if n > 0 {
                    handle_data(&mut core, &links, &mut data);
                }
            }
        }
        // hand committed blocks to the sequencer
        for block in core.consensus.drain_committed() {
            core.dissemination.on_committed(&block);
            let _ = links.committed.send(block);
        }
        // gossip targets follow the validator set of the height being decided
        let new_height = core.consensus.position().0;
        if new_height != height {
            height = new_height;
            links.refresh(&core);
        }
    }
}

fn on_tick(core: &mut Core, links: &Links) {
    let now = now_ms();
    match core.consensus.on_tick(now) {
        Ok(out) => links.outgoing(out),
        Err(e) => log_warn(format!("consensus tick failed: {e:#}")),
    }
    let set = core.consensus.current_validators();
    // seal every batch that is due (several if messages piled up)
    loop {
        match core.dissemination.seal_due(now, &set) {
            Ok(Some((batch, cert))) => {
                links.net.send_data(&links.all, batch);
                if let Some(cert) = cert {
                    on_own_cert(core, links, cert);
                }
            }
            Ok(None) => break,
            Err(e) => {
                log_warn(format!("failed to seal batch: {e:#}"));
                break;
            }
        }
    }
    for retry in core.dissemination.retries(now, &set) {
        match retry {
            Retry::Batch(bytes, to) => links.net.send_data(&to, bytes),
            Retry::Cert(cert) => on_own_cert(core, links, cert),
        }
    }
}

/// One of our batches is certified: queue it for proposing and tell every validator.
fn on_own_cert(core: &mut Core, links: &Links, cert: BatchCert) {
    if let Err(e) = core.consensus.add_certificate(cert.clone()) {
        log_warn(format!("own certificate refused: {e:#}"));
    }
    links.consensus_to(&links.validators, &PeerMsg::Cert(cert));
}

fn handle_input(core: &mut Core, links: &Links, input: Input) {
    let now = now_ms();
    match input {
        Input::Peer(msg) => {
            let result = match &msg {
                PeerMsg::Proposal(p) => core.consensus.on_proposal(p.clone(), now),
                PeerMsg::Vote(v) => core.consensus.on_vote(v.clone(), now),
                PeerMsg::Cert(c) => core
                    .consensus
                    .add_certificate(c.clone())
                    .map(|r| (r, vec![])),
                PeerMsg::Attestation(a) => {
                    let set = core.consensus.current_validators();
                    match core.dissemination.on_attestation(a.clone(), &set) {
                        Ok(Some(cert)) => on_own_cert(core, links, cert),
                        Ok(None) => {}
                        Err(e) => log_warn(format!("rejected attestation: {e:#}")),
                    }
                    return; // point to point, never relayed
                }
            };
            match result {
                Ok((Received::New, out)) => {
                    // relay, so it reaches everyone over any working link
                    let to = match msg {
                        PeerMsg::Cert(_) => &links.validators,
                        _ => &links.all,
                    };
                    links.consensus_to(to, &msg);
                    links.outgoing(out);
                }
                Ok((Received::Duplicate, out)) => links.outgoing(out),
                Err(e) => log_warn(format!("rejected peer message: {e:#}")),
            }
        }
        Input::Certified(block, reply) => {
            let _ = reply.send(core.consensus.on_certified_block(block));
        }
        Input::Query(f) => f(core),
    }
}

fn handle_data(core: &mut Core, links: &Links, items: &mut Vec<DataInput>) {
    let set = core.consensus.current_validators();
    let mut forward: Vec<Message> = Vec::new();
    for item in items.drain(..) {
        match item {
            DataInput::Batch(batch) => {
                let author = set.get(&batch.author).map(|v| v.address.clone());
                match core.dissemination.on_batch(batch, &set) {
                    Ok(Some(att)) => {
                        if let Some(addr) = author {
                            links.consensus_to(&[addr], &PeerMsg::Attestation(att));
                        }
                    }
                    Ok(None) => {}
                    Err(e) => log_warn(format!("rejected batch: {e:#}")),
                }
            }
            DataInput::Messages { messages, reply } if core.dissemination.is_validator() => {
                let verdicts = core.dissemination.submit(messages, now_ms());
                if let Some(reply) = reply {
                    let _ = reply.send(verdicts);
                }
            }
            DataInput::Messages { messages, reply } => {
                // not a validator: forward to the validators, which batch them
                let verdicts = messages.iter().map(|_| Ok(Received::New)).collect();
                forward.extend(messages.into_iter().map(|(_, m)| m));
                if let Some(reply) = reply {
                    let _ = reply.send(verdicts);
                }
            }
        }
    }
    if !forward.is_empty() {
        links.data_to(&links.validators, &DataMsg::Messages(forward));
    }
}
