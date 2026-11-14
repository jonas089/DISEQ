![Diseq](https://github.com/jonas089/DISEQ/blob/master/resources/DISEQ/DISEQ1.jpg)

The logos were created by [Imran Piash](https://www.fiverr.com/imranpiash?source=inbox). Rights have been granted to Jonas Pauli (the developer of this project).

# DISEQ Proof of Concept: Distributed Message Sequencing
Diseq is a distributed sequencer built by [Jonas Pauli](https://www.linkedin.com/in/jonas-pauli/), a blockchain research engineer from Switzerland.

> [!NOTE]
> Feel free to reach out and ask me any questions you may have regarding this project,
> I am always eager to exchange ideas and knowledge on consensus and distributed systems with fellow
> cryptographers & engineers.

Diseq is a distributed message sequencer: a validator set orders arbitrary messages into a chain of blocks
that are final as soon as they are committed. It is meant as a middle ground between a single centralized
sequencer and a fully decentralized, token-incentivized one. It runs as a fixed, permissioned set by default,
and the validator set rules can be swapped for proof of stake or anything else.

- **Data availability layer (Quorum Store / Narwhal style):** every validator batches its clients' messages and broadcasts the batches; a batch attested by more than 2/3 of the weight gets an availability certificate.
- **Consensus:** Tendermint-style BFT (propose, prevote, precommit, locking) over VRF-elected proposers. Blocks order batch certificates, not messages, so block size no longer limits throughput. Safe while less than 1/3 of the weight is faulty; no synchronized clocks needed.
- **Sequencer:** committed blocks are resolved into the final message sequence off the consensus path, with duplicates removed deterministically.
- **Proofs:** every sequenced message gets a Merkle inclusion proof against the state root (hexary Merkle Patricia trie).

# Code layout

| Crate | What | Start reading at |
|---|---|---|
| [`consensus/`](consensus) (`diseq-consensus`) | The protocol, free of I/O: types, VRF election, validator sets, Tendermint state machine, votes and equivocation handling, batch availability certificates. Deterministic and fully simulated in tests. | `consensus/src/lib.rs`, then `tendermint.rs` and `availability.rs` |
| [`node/`](node) (`diseq-node`, binary `l2-sequencer`) | Everything with I/O: the single-writer runtime, batch dissemination, the sequencer, networking (transport, peer routes, sync), the client API and RocksDB storage. | `node/src/lib.rs`, then `runtime.rs` |

```text
 clients ─► validator ─batch─► all validators ─attestation─► author ─► BatchCert (>2/3)
                                                                         │
 sequencer ◄── committed block (ordered certificates) ◄── Tendermint ◄───┘
     │
     └─► final message sequence (deduplicated) ─► Merkle trie ─► proofs
```

# Consensus

Each height runs rounds of Tendermint ([Buchman, Kwon, Milosevic 2018](https://arxiv.org/abs/1807.04938)), with the proposer chosen by VRF:

1. **Propose.** Every validator privately evaluates its VRF on `H(randomness(parent) || height || round)`.
   The output is unique per key and input and unpredictable to everyone else, so the leader is unknown until it proposes and can't be targeted ahead of time.
   Eligible validators broadcast a proposal: a block listing certified batches, with the VRF proof.
   A validator that knows a block with a 2/3+ prevote quorum (its *valid value*) re-proposes that block instead of a new one.
2. **Prevote.** When the propose timeout fires, or as soon as every validator has proposed, a validator prevotes for the best proposal its lock allows, or nil.
   Re-proposals backed by the most recent 2/3+ prevote quorum rank first, so honest validators converge on the block that locked validators can still vote for.
   Otherwise the lowest VRF priority wins. Priority is the exponential race `-ln(1-u)/weight`, so validators win in proportion to their weight.
3. **Precommit.** When a validator sees 2/3+ prevotes for a block in its round, it *locks* on that block and precommits it.
   On a nil quorum, or after the prevote timeout, it precommits nil.
4. **Commit.** 2/3+ precommits for a block, in any round, commit it.
   The precommits are stored with the block as its commit certificate, and nodes catching up verify them.

**Safety.** A locked validator only prevotes for its locked block, or for a block with a newer 2/3+ prevote quorum.
Two conflicting commits would therefore need more than 1/3 of the weight to equivocate.
Locks and own votes are persisted before they are sent, so a restart cannot cause double signing.

**Liveness.** Timeouts grow with each round, and a node jumps ahead when more than 1/3 of the weight is in a later round.
Validators re-broadcast their votes, plus the prevotes that justify their lock, until the height commits.
Votes from an equivocating validator are kept per value, so honest nodes that saw different votes from it still converge.

**Randomness.** A block's randomness comes from its author's VRF output, so changing block contents cannot bias the next election.

**Conflicts.** Two proposals from one proposer in one round are both dropped. Conflicting votes from one validator are kept per value and logged. A batch can be committed only once: a block naming an already committed batch is invalid. Duplicate *messages* (the same message in several batches, e.g. sent to two validators) are resolved by the sequencer, which keeps the first occurrence in chain order.

**Tests.** `consensus/tests/simulation.rs` runs a deterministic simulation with a Byzantine validator holding 1/4 of the weight.
It equivocates every proposal and vote toward every honest node, over a network that drops 30% of messages and reorders them until a global stabilization time.
Every step checks that honest nodes never commit conflicting blocks, and the run checks that they keep committing after stabilization.
`SIM_SEEDS=200 cargo test --release --test simulation` runs more seeds.

**Validator sets.** Validator sets come from a `ValidatorSetPolicy` (`consensus/src/validators.rs`). The default is `FixedValidatorSet`.
`EpochStakePolicy` is a proof-of-stake policy that rotates the top-N staked candidates at epoch boundaries. It takes a `StakeSource` (where stake comes from, e.g. an L1 staking contract read at a finalized block the chain references) and a `WeightFn` (how stake becomes voting weight: `Linear`, `SquareRoot`, or your own, e.g. a cap on any one validator's share).
Validators never claim a stake: every node computes the set itself from the chain, so votes and proposals are weighed by its own view. Implement `ValidatorSetPolicy` directly for any other rule set.

# Data availability

1. **Batching.** A validator collects client messages and seals them into a signed batch every `BATCH_INTERVAL_MS` or `MAX_BATCH_MESSAGES` messages, stores it and broadcasts it. Full nodes forward client messages to the validators.
2. **Attestation.** A validator that receives a valid batch stores it and signs an attestation for the author.
3. **Certificate.** Attestations from more than 2/3 of the weight form a `BatchCert`: at least one honest validator holds the batch and will serve it. Certificates go to every validator's proposal queue.
4. **Ordering.** Blocks list certificates (a few hundred bytes per batch), so consensus messages stay small no matter how much data flows, and all validators disseminate data in parallel.
5. **Sequencing.** After a block commits, each node loads the block's batches (fetching any it missed from peers), drops messages that were already sequenced, and records the result. `/get/height` is the last sequenced height.

Accepting a message is not finality: if a validator crashes before its batch is certified, the message is lost and the client resubmits (resubmitting is always safe). `/get/message/:id` reports the height a message was sequenced at.

Backpressure: validators keep at most `MAX_INFLIGHT_BATCHES` uncommitted batches and `MAX_PENDING_MESSAGES` unbatched messages; beyond that `/schedule` returns `503`.

**Storage.** RocksDB, one column family per concern (blocks, batch index, consensus state, batches, message index, sequencing output, trie). Blocks and the validator's own votes are synced to disk before they are acted on.

# Run a local network of 4 nodes with Docker

```bash
docker compose up
```

Nodes listen on `8080`-`8083`. Configuration is read from the environment:

| Variable | Default | |
|---|---|---|
| `LOCAL_VALIDATOR` | `0` | test key index `0-3`, or `none` for a full node |
| `API_HOST_WITH_PORT` | `0.0.0.0:8080` | listen address |
| `PATH_TO_DB` | `database` | RocksDB directory |
| `PEERS` | docker hostnames | comma separated addresses of the 4 default validators |
| `EXTRA_PEERS` | | non-validator peers that receive blocks and batches (e.g. full nodes) |
| `PROPOSE_TIMEOUT_MS` / `PREVOTE_TIMEOUT_MS` / `PRECOMMIT_TIMEOUT_MS` | `1000` / `1000` / `1000` | round timeouts |
| `TIMEOUT_DELTA_MS` | `500` | added to each timeout per round |
| `REBROADCAST_INTERVAL_MS` | `2000` | vote retransmission interval |
| `GENESIS_TIMESTAMP` | `1725000000` | must match on all nodes |
| `EXPECTED_PROPOSERS` | unset | enable VRF sortition with ~N candidates per round |
| `ALLOW_EMPTY_BLOCKS` | `false` | propose heartbeat blocks without batches |
| `MAX_BATCH_MESSAGES` / `BATCH_INTERVAL_MS` / `BATCH_RETRY_MS` | `4096` / `20` / `1000` | batch sealing and retransmission |
| `MAX_PENDING_MESSAGES` / `MAX_INFLIGHT_BATCHES` / `MAX_PENDING_BATCHES` | `200000` / `256` / `10000` | backpressure limits |
| `MAX_BLOCK_MESSAGES` / `MAX_BLOCK_BATCHES` / `MAX_MESSAGE_BYTES` | `1000000` / `1000` / `65536` | size limits |
| `TICK_INTERVAL_MS` / `SYNC_INTERVAL_MS` | `10` / `2000` | timer resolution, block sync interval |

`cargo test --release` runs the unit tests, the adversarial consensus simulation, and an in-process HTTP network of 4 validators and a full node (`node/tests/e2e.rs`).

# API

## Clients (JSON; bincode bodies with `Content-Type: application/octet-stream`)
| Route | |
|---|---|
| `POST /schedule` | submit one message `{"data": [..], "timestamp": n}` |
| `POST /schedule/batch` | submit many messages |
| `GET /get/height` | last sequenced height |
| `GET /get/block/:height` | block (batch certificates, votes) and its final message sequence |
| `GET /get/message/:id` | height a message was sequenced at (`null` until final) |
| `GET /get/state_root` | Merkle root over all sequenced message ids, and the height it covers |
| `GET /merkle_proof/:id` | membership proof; verify with `ciphercurve_trie::verify(root, id, id, proof)` |
| `GET /get/status` | consensus / sequenced / trie heights, queue sizes |
| `GET /get/validators` | active validator set |

## Peers (bincode)
| Route | |
|---|---|
| `POST /p2p/consensus` | proposals, votes, attestations, batch certificates |
| `POST /p2p/data` | batches, forwarded client messages |
| `GET /p2p/height`, `GET /p2p/block/:height` | block sync |
| `POST /p2p/batches` | fetch batches by digest |

# Merkle Proofs
Every sequenced message id is inserted into a hexary [Merkle Patricia Trie](https://github.com/jonas089/ciphercurve-trie), off the consensus path and one batch per block range. A membership proof can be obtained for every message, see `node/tests/e2e.rs`.

©️ Ciphercurve GmbH, 2025
