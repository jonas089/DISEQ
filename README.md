# Distributed Transaction Sequencer
Read the full [Litepaper](https://github.com/jonas089/zk-vrf-consensus/tree/master/whitepaper)

> [!Warning]
> I experimented a lot with Mutex and Rwlock, but
> now decided that I'll want to use permanent storage 
> for consensus tasks instead. That'll help prevent 
> deadlocks moving forward.
> This is a relatively big task so not sure yet when I'll be done with it.
> Consider this sequencer a work in progress research project, not production software!


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
Whenever a Block is stored, all transactions in that block are inserted into the custom [Merkle Patricia Trie](https://github.com/jonas089/jonas089-trie).

My Trie library supports merkle proofs which will be exposed by the sequencer API - inclusion can be proven for individual transactions.

I will likely add support for the eth-trie crate soon, but for this project I chose to be extra fancy and write a custom Trie from scratch.

Each Transaction has a `Key` that is unique. The `Key` is generated like this:

```rust
        let mut leaf = Leaf::new(Vec::new(), Some(transaction.data.clone()));
        leaf.hash();
        leaf.key = leaf
            .hash
            .clone()
            .unwrap()
            .iter()
            .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1))
            .collect();
        leaf.hash();
        let transaction_key_json = serde_json::to_string(&leaf.key).unwrap();
        let merkle_proof_response = client
            .post("http://127.0.0.1:8080/merkle_proof")
            .header("Content-Type", "application/json")
            .body(transaction_key_json)
            .send()
            .await
            .unwrap();
```

The example above includes a request that will obtain a merkle proof for the Transaction that belongs to this `Key`.

The merkle proof can be verified against the Root Hash of the Trie that it was requested for:

```rust
        ...
        let transaction_key_json = serde_json::to_string(&leaf.key).unwrap();
        let merkle_proof_response = client
            .post("http://127.0.0.1:8080/merkle_proof")
            .header("Content-Type", "application/json")
            .body(transaction_key_json)
            .send()
            .await
            .unwrap();
        let merkle_proof_json = merkle_proof_response.text().await.unwrap();
        let merkle_proof: MerkleProof = serde_json::from_str(&merkle_proof_json).unwrap();
        let state_root_hash_response = client
            .get("http://127.0.0.1:8080/get/state_root_hash")
            .send()
            .await
            .unwrap();
        let state_root_hash: Root =
            serde_json::from_str(&state_root_hash_response.text().await.unwrap()).unwrap();
        let mut inner_proof = merkle_proof.nodes;
        inner_proof.reverse();
        println!("Inner Proof: {:?}", &inner_proof);
        verify_merkle_proof(inner_proof, state_root_hash.hash.unwrap());
        ...
```

Note that `verify_merkle_proof` will revert if the merkle proof is invalid / doesn't sum up to the provided Trie Root.