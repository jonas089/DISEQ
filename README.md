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

- **Leader election:** standard VRF (schnorrkel/sr25519), Algorand/Praos-style self-selection.
- **Consensus:** Tendermint-style BFT (propose, prevote, precommit, locking). It is safe while less than 1/3 of the weight is faulty and does not rely on synchronized clocks.
- **Mempool:** messages submitted to any node are gossiped to all nodes and pulled through anti-entropy, so whichever validator wins the election sequences them.
- **Proofs:** every committed message gets a Merkle inclusion proof against the state root.

# Consensus

Each height runs rounds of Tendermint ([Buchman, Kwon, Milosevic 2018](https://arxiv.org/abs/1807.04938)), with the proposer chosen by VRF:

1. **Propose.** Every validator privately evaluates its VRF on `H(randomness(parent) || height || round)`.
   The output is unique per key and input and unpredictable to everyone else, so the leader is unknown until it proposes and can't be targeted ahead of time.
   Eligible validators broadcast a proposal with the VRF proof.
   A validator that knows a block with a 2/3+ prevote quorum (its *valid value*) re-proposes that block instead of a new one.
2. **Prevote.** When the propose timeout fires, a validator prevotes for the best proposal its lock allows, or nil.
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

**Tests.** `tests/consensus_sim.rs` runs a deterministic simulation with a Byzantine validator holding 1/4 of the weight.
It equivocates every proposal and vote toward every honest node, over a network that drops 30% of messages and reorders them until a global stabilization time.
Every step checks that honest nodes never commit conflicting blocks, and the run checks that they keep committing after stabilization.
`SIM_SEEDS=50 cargo test --test consensus_sim` runs more seeds.

**Validator sets.** Validator sets come from a `ValidatorSetPolicy` (`src/consensus/validators.rs`). The default is `FixedValidatorSet`.
`EpochStakePolicy` is a reference proof-of-stake policy that rotates the top-N staked candidates at epoch boundaries.
Implement the trait for any other rule set.

# Mempool

`/schedule` stores a message in the local mempool, which is deduplicated by message id and bounded,
and gossips it to all peers; peers relay messages that are new to them. A periodic anti-entropy pass
pulls message ids from every peer and fetches missing messages, so messages also spread when gossip
fails. Proposers take the oldest pooled messages, and committed messages are removed from every pool
and can never be sequenced twice.

# Run a local network of 4 nodes with Docker

```bash
docker compose up
```

Nodes listen on `8080`-`8083`. Configuration is read from the environment:

| Variable | Default | |
|---|---|---|
| `LOCAL_VALIDATOR` | `0` | test key index `0-3`, or `none` for a full node |
| `API_HOST_WITH_PORT` | `0.0.0.0:8080` | listen address |
| `PATH_TO_DB` | `database.sqlite` | SQLite file (blocks, mempool, trie) |
| `PEERS` | docker hostnames | comma separated addresses of the 4 default validators |
| `EXTRA_PEERS` | | additional gossip targets (e.g. full nodes) |
| `PROPOSE_TIMEOUT_MS` / `PREVOTE_TIMEOUT_MS` / `PRECOMMIT_TIMEOUT_MS` | `3000` / `1000` / `1000` | round timeouts |
| `TIMEOUT_DELTA_MS` | `500` | added to each timeout per round |
| `REBROADCAST_INTERVAL_MS` | `2000` | vote retransmission interval |
| `GENESIS_TIMESTAMP` | `1725000000` | must match on all nodes |
| `EXPECTED_PROPOSERS` | unset | enable VRF sortition with ~N candidates per round |
| `ALLOW_EMPTY_BLOCKS` | `false` | propose heartbeat blocks with an empty mempool |
| `MAX_BLOCK_MESSAGES` / `MAX_POOL_SIZE` / `MAX_MESSAGE_BYTES` | `10000` / `100000` / `65536` | limits |

`cargo test` runs the unit tests, the adversarial consensus simulation, and an in-process HTTP network (`tests/e2e.rs`).

# API Routes

## Clients
```rust
        .route("/schedule", post(schedule))
        .route("/merkle_proof", post(merkle_proof))
        .route("/get/block/:height", get(get_block))
        .route("/get/height", get(get_height))
        .route("/get/state_root_hash", get(get_state_root_hash))
        .route("/get/validators", get(get_validators))
        .route("/get/pool", get(get_pool))
```
## Peers
```rust
        .route("/gossip/message", post(gossip_message))
        .route("/propose", post(propose))
        .route("/vote", post(vote))
        .route("/get/pool/ids", get(get_pool_ids))
        .route("/get/pool/messages", post(get_pool_messages))
```

# Merkle Proofs
Whenever a block is committed, its messages are inserted into the custom [Merkle Patricia Trie](https://github.com/jonas089/jonas089-trie)
and the new root is persisted. A Merkle proof can be obtained for every message, see `tests/e2e.rs`.

©️ Ciphercurve GmbH, 2025
