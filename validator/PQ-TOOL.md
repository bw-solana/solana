# Actual Agave PQ test client

`agave-pq-tool` creates actual Agave `GenesisConfig` ledgers and submits ordinary
versioned Agave messages through the validator's JSON RPC API. It uses
`solana_runtime::pq` to construct Falcon authorization witnesses. Transfers,
proof account uploads, verification and migration execute in the actual Bank,
SVM and AccountsDB.

Commands take a JSON request file:

```text
agave-pq-tool init /private/init.json
agave-pq-tool load /private/load.json
agave-pq-tool proof /private/proof.json
agave-pq-tool migrate /private/migrate.json
agave-pq-tool probe-shared-authority /private/probe.json
agave-pq-tool resume-rich-migration /private/resume.json
agave-pq-tool soak /private/soak.json
agave-pq-tool soak-pipelined /private/soak.json
agave-pq-tool bench /private/bench.json
```

An initialization request supplies `directory` (fresh, absolute and outside the
repository), `hosts` (at least four IPs), `pq_port`, `rpc_port`,
`start_unix_ms`, `slot_count` (4–18,000, multiple of four), `block_time_ms`,
`network_delay_ms` (default 500; 1–10,000),
`target_block_bytes`, `max_transactions`, `wallet_count`, and `recipient_count`
(default 1; 1–1024). Recipients are distinct System accounts, each prefunded with
one billion lamports and separate from the signing wallets. Each recipient has
a separate Falcon key and a fresh identity policy, so deposited assets remain
controlled. Optional
`public_seed_fixture` configures a synthetic migration test using that fixture's
existing signature domain and migration context. It does not generate a new
proof or pretend the fixture proves an unrelated intent.

Long runs use one explicitly provisioned finite Ax epoch; signing histories are
never reset to extend it. The pinned Ax descriptor is 1,704 bytes including its
Falcon binding. At 18,000 slots, an individual role witness includes WOTS
material, its private-leaf disclosure and a depth-19 authentication proof in
1,997 bytes. The complete raw public material is approximately 5.6 MiB and stays
local; it is not transmitted as one transport frame. Network evidence carries
the compact descriptor and authenticated role witness.
The immutable `cutoff_slot` defaults to zero. With `legacy_wallet_count`, the
first wallets instead have actual Ed25519 addresses, separate replacement Falcon
keys and no genesis authorization policies. Use a future cutoff to allow genuine
onchain enrollment before legacy signatures become inadmissible.

Optional `enable_spl_programs` installs the repository's real SPL program ELFs,
mint and associated token accounts for wallets and recipients. `enable_workload`
installs the real upgradeable SBPFv3 application fixture. `workload_state_count`
creates program-owned legacy authority accounts backed by CPI escrow PDAs and
two application signers; it requires two legacy actors per state plus a separate
legacy System sponsor. `background_state_accounts` adds up to 10,000 padded
program-owned accounts. `state_data_bytes` defaults to 2,048, includes nonzero
padding and has a 64 MiB aggregate bound. `rich_seed_fixture` creates application
state, a funded PDA and optional SPL custody at the seed fixture's original
address for a real post-break recovery test. Private keys remain outside Git.

PQ ports use `pq_port + node_index`; RPC ports use `rpc_port + 4 * node_index`
to leave room for pubsub. The manifest contains each node's `host`, `config`,
`identity`, `rpc_port`, `rpc_url`, `ledger`, `keys` and real vote/stake addresses.
Credentials and key directories have private Unix permissions. Existing
directories and signer histories are never overwritten.

Optional `execution_threads` selects 1–32 native execution workers (default 8).
Optional `proposal_target_block_bytes` and `proposal_max_transactions` select
smaller local production caps within the immutable consensus byte/count limits.
They control proposer selection; peers continue validating against the pinned
consensus maximum. Benchmark changes to worker counts or proposal caps require
recording every node's current configuration and preserving its existing ledger,
Ax signer state, monotonic store and release journal. The cluster helper also
accepts an explicit `--rayon-global-threads` value (default 8); that pool controls
other global Rayon work and is separate from the configured execution pool.

Genesis has real vote and delegated stake accounts for each validator. Their
authorized identity has a separate account Falcon key and a trusted genesis
policy documenting pre-cutoff consent. Network, leader and account Falcon keys
are separate; durable Ax state and its monotonic store are preserved. The
signature domain and constitutional PQ role registry are actual program-owned
genesis accounts. The completed Agave genesis hash and frozen activation Bank's
48-byte state commitment are pinned separately. The initializer computes that
checkpoint from the serialized genesis validators actually load.

A load request supplies `manifest` and `count`, with optional `wallet_index`,
`start_index`, `rpc_urls`, `connections` (default 16), `signing_threads` (64),
`batch_size` (16), `timeout_seconds` (180), and `output`. Transfer `i` sends
`start_index + i + 1` lamports to the manifest's funded recipient. Dedicated
generators must use disjoint `start_index` ranges and/or distinct wallets.
For concurrent generators sharing the recipient, the coordinator supplies the
same optional `expected_recipient_balance` (starting balance plus all generators'
transfer sums) to each request. Each loader waits for its own finalized IDs and
then checks every validator against that absolute total. Its reported TPS counts
its own transactions; aggregate throughput uses the coordinator's total and
common observation interval.
For distributed account workloads, `wallet_indices` selects distinct funded
wallets and rotates the payer for each transfer; `recipient_count` selects the
first recipients from the manifest (default 1). Transfer `i` chooses recipient
`(start_index + i) % recipient_count`, allowing independent generators to
calculate the same destination totals from disjoint global index ranges.
The coordinator supplies `expected_recipient_balances`, one absolute balance
per selected recipient, when running concurrent generators. The vector and
the older scalar balance option are mutually exclusive. Each validator's
balances are fetched through JSON-RPC HTTP batches with exact response-ID
validation, and every recipient must reach its expected balance. Results include
the selected wallet indices, recipient addresses, per-recipient transfer sums,
and complete before/after/expected balance vectors; the older scalar result
fields describe the first recipient. Older manifests without a recipients
vector continue to use their original funded recipient.
These varying amounts provide distinct transaction intents without depending
on an unavailable Memo program. The loader checks every returned ID, all
node-zero finalized signature statuses, and recipient balances at every URL.
Its throughput includes generation, submission and finality observation; it is
not a claim about unseen protocol completion timestamps. `transfer` accepts
the same request with `count: 1`.
Accepted IDs are saved before finality polling, including partial admission
failures. With `output`, the ID file uses the `.ids.json` extension; without it,
a fresh private ID file is created in the manifest directory. Failure reports
use `.ids.failure.json`, bounded error text and at most 64 pending examples.
Pending statuses are polled in round-robin batches of at most 256; a missing
early batch cannot hide later finalized IDs. Counts describe observed statuses.
Historical status lookup is used when available, with live Bank lookup retained
for nodes that explicitly report transaction history is disabled.

Proof requests supply `manifest`, `replacement_private_key`, optional
`public_seed_fixture`, `sponsor_wallet`, `rpc_url`, `timeout_seconds`, and
`output`. Creation finalizes first, then ordered 8 KiB writes are pipelined on
one HTTP client. `skipPreflight` prevents simulation against the earlier upload
offset; mandatory RPC Falcon authentication and the Bank's check under account
locks still run. After all writes finalize, the client seals the account,
submits the actual native verifier with a 1.4 million CU limit, finalizes the
policy, spends using the proved replacement key, and closes the upload. It
checks the actual installed `OriginalSeed` policy, spend and closure at every
validator. The reported verifier transaction time includes consensus finality;
it does not isolate CPU spent in the verifier.
With RPC transaction history enabled, the client additionally fetches each
validator's actual finalized verification transaction, checks the exact native
VerifySeed instruction and its upload/sponsor accounts, and reports its slot,
error, compute units, cost units and logs. Missing history/receipts are reported
explicitly. Receipt CU must show the native verifier's million-unit charge.
For a rich seed target, the client preserves the installed program-owned state
and then uses the recovered Falcon authority for real PDA withdrawal and SPL
spending. Every validator must retain the application padding, mint supply,
token ownership and expected asset deltas. The close check reconciles the
sponsor's exact receipt fees and policy rent against its initial balance.

Migration requests supply `manifest`, `output`, and optional `sponsor_wallet`
(last legacy wallet), `rpc_url`, `timeout_seconds` (180), `wait_for_cutoff` (true)
and `exercise_rich_state` (true). The client performs actual Ed-signed application
and SPL operations, uploads and installs every actor's Falcon policy through
native instructions, and enrolls the System sponsor last. It preserves the old
32-byte addresses and account owner/data. After cutoff it exercises multiparty
Falcon authorization, PDA CPI, exact fee-charged failure rollback, sponsored
Falcon rotation of program-owned authorities, application authority rotation
and complete PDA asset/rent withdrawal. Every validator's policies, application
bytes and SPL supply/ownership/balances are checked. Token snapshots use native
`getMultipleAccounts` batches of at most 100 with exact response lengths,
retaining the same owner, rent and byte-preservation checks. The original manifest stays
as pre-migration evidence; the reported `.migrated-manifest.json` records the
new private key paths after finalized rotations.

The constrained resume uses the same migration request schema. It supports the
observed interruption after the first vault's application rotation: exactly
172 committed transactions, first vault sequence seven with generation-two
Falcon policy and matching saved replacement key, remaining fifteen vaults at
sequence three with generation-one policies, all 33 authorities enrolled and
cutoff reached. Every validator's complete application bytes, policies, PDA
collateral, mint and 801 token balances must match that exact stage before any
new transaction is submitted. It uses the pinned serialized genesis as the
token and padding baseline, writes a pre-resume observation artifact, finishes
the first drain and the remaining lifecycles, and checks exactly 151 new and
323 total committed transactions. Other interruption stages fail closed and
need a broader durable client recovery design. Validator state and signing
histories are preserved throughout.

The shared-authority probe supplies the completed `migrated-manifest.json`,
`sponsor_wallet`, fresh `output`, and optional `state_count` (4), `rpc_url` and
`timeout_seconds` (180). It uses original authority zero's finalized rotated
Falcon key to control other existing application states that still reference
its original 32-byte address and authority one as a second signer. It initializes
and deposits to their real PDAs, performs multisig withdrawal, checks exact
fee-charged CPI rollback, and drains all escrow assets and rent. Every validator
must retain the shared authority references, application owner/rent/padding and
the original authority's separately rotated application state. Results list the
affected background states and their complete expected final public account
bytes so subsequent large-state scans can check those transitions explicitly.
Run it before traffic that uses the same sponsor or recipient balance.

Continuous requests supply `manifest`, `source_id`, distinct `wallet_indices`,
`recipient_count`, `duration_seconds`, `phases`, and a fresh private `output`.
Each phase has `seconds`, `target_tps` and `kind` (`system_transfer`,
`token_transfer`, or `nonce_only`); phase durations must sum to the requested
duration. Optional fields are `start_counter`, `rpc_urls`, `connections` (16),
`signing_threads` (64), `batch_size` (16), `max_outstanding` (4,096),
`status_poll_ms` (100; use 10 for higher observation rates),
`drain_timeout_seconds` (180), `id_sample_stride` (100), `amount` (1), and
`compute_unit_limit` (20,000). Each signed message includes a genuine SBF nonce
instruction binding the source and counter. Selected fee payers must be
controlled System accounts without data. Independent sources must use distinct
source IDs, counters and payer sets.

The continuous client applies bounded admission queues and finality backpressure,
refreshes native blockhashes, and polls exact transaction IDs in round-robin
batches. It reports RPC admission separately from actual rooted onchain success
and error counts. Minute JSONL records include phase/rate, latency, outstanding
counts and all validators' native status and SOL/token balance vectors. Failed
IDs and sampled successes stream to JSONL; pending IDs are retained on failure.
Final output reports actual successful recipient deltas, a SHA384 observation
digest, first/last admission times and their monotonic span. It drains its own
transactions, then waits for all-node balance convergence. A coordinator running
multiple sources must reconcile the sum of their actual successful deltas
against a common pre-start baseline; RPC acceptance is insufficient evidence of
throughput. Use a duration above 3,600 seconds and check the actual admission
span when demonstrating at least one hour of continuous traffic.

The opt-in `soak-pipelined` accepts the same request and moves observation off
the generation loop. Polling freezes the maximum pending counter for each
finite pass before wrapping, so a continuous stream of new arrivals cannot
starve older identities whose earlier lookup returned null. Four status workers
share at most eight 256-ID jobs; each
admitted counter/signature can have only one query in flight. A single bounded
minute-audit worker collects all-node balances/status without pausing signing.
JSON-RPC response IDs, row counts, errors, and each exact pending identity are
checked before finality accounting; out-of-order batch completion is supported.
The client still reconciles every pending transaction, drains audits, joins all
workers and fails on any admission/execution error. Reports add worker bounds,
status RPC timing and in-flight maxima. Those timings describe observation
overhead, while throughput counts actual rooted execution. Compare its native
rooted counts and final asset/fee deltas against the synchronous client under
the same offered load and validator binary; faster observation alone does not
establish higher validator capacity. The synchronous `soak` command remains
available, and measured runs retain their original binary/source provenance.
The `latency_millis_*` counters and sampled `latency_ms` measure reservation
through the source's finalized-status observation; they include queueing and
polling delay. They are not native consensus finality measurements. Joining
sampled signatures/slots to validator root-publication timestamps separates
native finality from delayed source observation.

Bench requests supply a fresh private `directory`, `count`, `wallet_count`
(for example 8 or 64), `signing_threads`, `block_size` (maximum 500), and
optional `output`. The comparison uses identical wallet addresses and System
Program transfer workloads in real Banks. Default Ed25519 explicitly receives
full signature verification; PQ receives early authorization and authoritative
verification under account locks. Banks advance through bounded blocks with
ticks, freeze and root updates. Signing, early authentication, SVM execution
and freezing have separate wall and process CPU measurements. PQ freezing
includes computation of the wide SHA384 account-state commitment required for
native certification; a separately timed query reads that cached commitment.
Bank setup is
excluded; RSS from `getrusage` is cumulative, with default measured before PQ.
This is a Bank microbenchmark, and includes no network or consensus throughput.
Results identify the CPU model, available logical CPUs and selected Falcon
backend. Supported x86 CPUs use the pinned vendor's AVX2 implementation; other
CPUs retain the portable CLEAN implementation with the same keys and wire format.
