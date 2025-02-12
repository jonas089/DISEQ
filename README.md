# DISEQ Proof of Concept: Distributed Message Sequencing
Diseq is a distributed sequencer built by [Jonas Pauli](https://www.linkedin.com/in/jonas-pauli/), a blockchain research engineer from Switzerland.

> [!NOTE]
> Feel free to reach out and ask me any questions you may have regarding this project,
> I am always eager to exchange ideas and knowledge on consensus and distributed systems with fellow
> cryptographers & engineers.

Diseq acts as a distributed alternative to centralized (or decentralized) sequencing. Based on a novel zero knowledge consensus with deterministic validator selection, Diseq can operate with 51% percent of a fixed validator set being active and honest. Messages are added to a mempool and stored in the block once consensus has concluded and sufficiently many signatures from active nodes were collected. Nodes synchronize blocks to keep an immutable record of the message sequence.

Read the full [Litepaper](https://github.com/jonas089/zk-vrf-consensus/tree/master/whitepaper).

If you are an expert then consider also reading [some context about BFT](https://github.com/jonas089/zk-vrf-consensus/blob/master/whitepaper/byzantine-fault.md).

# Recommended: Run a local network of 4 Nodes with Docker
I began taking this passion project quite seriously, so I added an SQLite DB to store Blocks and Transactions.
Transactions are still read as a single chunk so the txpool for each Block must fit in memory, I do intend to change this.

To run the docker image with 2 nodes that will each have a db e.g. node-1.sqlite, node-2.sqlite where the temporary txpool and all
finalized Blocks are stored, run:

```bash
docker compose up
```

Port forwarding should make the nodes available a `8080` and `8081`. I plan to simulate larger networks in the future but for now it is designed
to spawn 2 instances that synchronize blocks and commit to proposals / contribute to consensus. The default consensus threshold is `1` - see `config` directory.

# API Routes

## Internal
```rust
        .route("/schedule", post(schedule))
        .route("/commit", post(commit))
        .route("/propose", post(propose))
        .route("/merkle_proof", post(merkle_proof))
```
## External
```rust
        .route("/get/pool", get(get_pool))
        .route("/get/commitments", get(get_commitments))
        .route("/get/block/:height", get(get_block))
        .route("/get/state_root_hash", get(state_root_hash))
```

To view a Block when running the example setup, request `127.0.0.1:8080/get/block/<id>`, or `127.0.0.1:8081/get/block/<id>`.

# Merkle Proofs
Whenever a Block is stored, all messages in that block are inserted into the custom [Merkle Patricia Trie](https://github.com/jonas089/jonas089-trie).
For every individual message in the trie a merkle proof can be obtained. See an example for this [here](https://github.com/jonas089/distributed-sequencer/blob/master/tests/api.rs).
