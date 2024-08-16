# PoRD-SQ: Semi-decentralized Sequencer based on my ZK Consensus Protocol
⚠️ This Project is not production ready and in a Research stage of development ⚠️

This project is based on my half-baked consensus protocol [Proof of Random Delta](https://github.com/jonas089/PoRD)

Read the PoRD whitepaper [here](https://github.com/jonas089/PoRD/tree/master/whitepaper)

# What is the motivation behind this product?
Decentralized sequencing is a huge challenge in the L2 Blockchain space and many companies are developing solutions
that are overly complex with respect to consensus (and tokenomics). Having reviewed some existing approaches and 
"work-in-progress" repositories, I decided that we want something more straightforward and are willing to compromize the
degree of decentralization.

In my personal opinion [PoRD](https://github.com/jonas089/PoRD) establishes a good balance of decentralization and 
simplicity. Because of this I have decided to implement a general-purpose node on top of the PoRD abstract / "whitepaper" - I know that at the time of writing PoRD is not 
mathematically sophisticated enough to be called a real "whitepaper" - anyways, this is a functional approach with reasonable security guarantees, not a theoretically bulletproof one.

It was pointed out that the ZK Random number generator can be replaced with a general VRF, I am researching this and might choose to replace the ZK Randomness with a VRF if it makes sense (as it will likely be faster).

# How does PoRD-SQ work?
PoRD Nodes collect arbitrary Transactions and store them in a temporary database (a transaction pool). Every era the PoRD consensus ceremony is held to select a validator from the fixed validator set to create the next Block. This selection process is based on perfectly deterministic, yet difficult to predict, Zero Knowledge random numbers | VRF numbers.

# Run basic E2E test with 2 Nodes (manually, in-memory)
Split your terminal into 2 sessions and run:
```bash
API_HOST_WITH_PORT=127.0.0.1:8081 LOCAL_VALIDATOR=1 cargo run
```
in Terminal A,

and

```bash
cargo run
```
in Terminal B

This will start the Network and initiate the Block generation process:
![example](https://github.com/jonas089/PoRD-sequencer/blob/master/resources/demo.png)

To submit an example Transaction to both nodes, run:

```bash
cargo test test_schedule_transactions
```

Note that currently only the Transactions stored in the Block-creating validator's pool are included in the block.
For a validator to commit it's pool it must win a consensus round, there is currently no synchronization between nodes other
than Block synchronization.

# API Routes

## Internal
```rust
        .route("/schedule", post(schedule))
        .route("/commit", post(commit))
        .route("/propose", post(propose))
```
## External
```rust
        .route("/get/pool", get(get_pool))
        .route("/get/commitments", get(get_commitments))
        .route("/get/block/:height", get(get_block))
```

To view a Block when running the example setup, request `127.0.0.1:8080/get/block/<id>`, or `127.0.0.1:8081/get/block/<id>`.

# Peers going offline
When peers go offline they will be ignored during the consensus phase. Should such a node re-join the network, then it will catch up with the valid Blocks that were generated
during its downtime. The network will continue so long as sufficiently many nodes e.g. at least >50% of the validator set are online and able to participate during
the consensus phase. Should less than >50% be available during the consensus phase, then currently there is a risk of the network getting stuck.

# Merkle Commitments
*Merkle Commitments are yet to be implemented, I am working on them.*
Whenever a Block is accepted, all transactions in that block are inserted into the custom [Merkle Patricia Trie](https://github.com/jonas089/jonas089-trie).
The Key for each transaction is a hash over its body (in the future nonces should be appended to handle duplicates | or duplicates should be rejected | or duplicates replace existing transactions).

Todo: Merkle Proofs against a root hash can be requested from the API. The Node must maintain the Root History and serve proofs on demand.

