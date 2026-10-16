# Experimental PQ integration in Agave

This directory contains shared cryptographic primitives. The validator, Bank,
SVM, native program, RPC, QUIC and RocksDB integration lives in the actual Agave
workspace crates. The earlier `pq-prototype` server and reference Bank are not
used by `agave-validator --experimental-pq-config`.

## Execution and authority

`runtime/src/pq.rs` rechecks each transaction's current Falcon policy both at
ingress and under Agave's actual account locks before SVM execution. Its existing
bounded 65,536-entry positive exact-math cache can reuse successful vendor
verification only for the exact full key, chain, domain, canonical message and
signature after fresh policy checks; misses and eviction can rerun mathematics.
Main30 adds a separate one-entry-per-thread canonical signature parser shortcut,
which caches no authentication decision. The canonical authentication PDA is
an ordinary program-owned account in AccountsDB. Installation and rotation
serialize with signer transactions. The native program in
`runtime/src/pq_program.rs` creates rent-funded upload PDAs through System
program CPI, seals uploads, verifies the complete private RFC8032 seed proof,
and atomically installs the replacement policy at the original 32-byte address.
Finalization permanently marks the proof consumed. The sponsor can then close
the upload account and recover its remaining lamports.

The carrier uses the existing SDK `VersionedTransaction` and a first native
authentication instruction containing padded Falcon witnesses. Its 64-byte
signature fields identify transactions; Falcon authorizes the signers. An
exact SHA384 replay identity covers the complete canonical message with randomized
witnesses zeroed. It is rebuilt through native journal execution; PQ execution
from a classical snapshot lacking that replay state fails closed. This
is an experimental ABI bridge, and requires a PQ-aware signing client.

At and after the immutable cutoff, unmigrated classical account signers are
rejected. Native Ed25519/secp256k1/secp256r1 verification, secp256k1
recovery, legacy BLS certificate verification and both classical EC proof-program
entrypoints (including CPI) are disabled. Application programs which implement classical
cryptography themselves still require explicit application migration: arbitrary
SBF code can implement an old signature verifier without calling a disabled
precompile. The runtime does not rewrite such programs or their stored permits.
The required first AUTH instruction also conflicts with the stock durable-nonce
layout, which requires AdvanceNonce first; that transaction lifetime is not
supported by this carrier.

## Validator and persistence

The current Main30 build retains private descendant execution before parent body
WAL and unsigned same-leader preparation before parent intent/sealing. It also
borrows journal inputs, removes redundant encoding/snapshots, overlaps one exact
journal append with previously authorized work, indexes full48 finalized
membership, separates journal/body locks, uses byte-exact native storage SHA384,
and parallelizes canonical DATA decoding and Ax authentication for the same
bounded receive batch. It adds no execution loop or full account-state copy.
The [implementation and remaining gates](docs/native-overlap-main24-to30.md)
explain what still runs serially.

All **216 unique functional tests**, **three separate release microbenchmarks**,
strict lint, formatting, optimized builds and actual R-genesis compatibility pass
on the exact final source. [Validation](results/optimized-native-agave/validation-release30/native-overlap-and-parallel-auth/README.md)
is separate from runtime evidence. R30 fully accepted its matched short at
**10,985.9625 TPS**, pressure short at **12,918.8914 TPS**, and predeclared
**3,660-second, 8k/s-total hour at 7,996.5247 TPS**, all including drain.
The [actual report](results/optimized-native-agave/profiling/pilot-r-main30-accepted-hour/README.md)
preserves rates, per-machine resources and timing scopes. The [same-Main30
ordinary reference](results/optimized-native-agave/profiling/ordinary-main30-vs-pq-r30/README.md)
also passed both owners, full audits and cleanup: **9.6 million** successful
transactions at **15,995.0415 TPS** including drain, with 600 seconds of traffic
at 16k/s total. PQ short targets were configured at 16k/s and 32k/s total; bounded
backpressured sources actually admitted 12,704.44/s and 14,481.11/s over their
120-second intervals. The hour admitted 7,998.68/s over 3,660 seconds. Earlier
rejected sustained attempts remain rejected; the lower R30 hour target and
bundled changes do not isolate a fix or peak gain.

PQ load acceptance uses every-ID source-finalized observations, all-eight native
slot/count histories and full account/balance/fee/background oracles. It does not
retain exhaustive per-load-ID status vectors on every validator. The separate
607-transaction migration/recovery prelude has complete full64-signature archives
on all eight: 587 successes and 20 deliberate charged failures. The ordinary
reference checked every one of its 9.6 million source signatures on all eight
replicas. It uses the same modified binary with native ordinary services,
classical signatures and default caps; the different 600-second duration does
not establish untouched production, a hardware ceiling or pure crypto overhead.


`core/src/validator.rs` starts the PQ service after loading genuine genesis,
BankForks, AccountsDB and Blockstore. It does not start classical gossip,
repair, TPU, TVU, PoH, block creation or BLS voter authority services in this
mode. Competing candidates execute in isolated genuine AccountsDB instances,
with private replay and SVM program caches, so same-slot forks cannot overwrite
each other. Independent transactions execute in bounded parallel native Bank
batches, with dependency order and native account locks preserved. Child views
share immutable parent state and retain account writes as deltas. Certification
checks the exact payload, parent, native transaction count and complete 48-byte
commitment, then promotes the same frozen Bank without another SVM execution.
Synced receipt publication precedes RPC confirmation. Genuine SBF execution and a deployed program's
visibility in descendant forks are tested. Each frozen candidate binds a
domain-separated SHA384 Merkle commitment over the actual accounts and Bank
metadata. Quantumglow selects and roots these genuine frozen Agave Banks.
Falcon binds candidate batches and final extents, and durable Ax signs consensus
evidence. A local producer syncs its exact complete payload intent before Falcon
signing and DATA/terminal streaming. A signed terminal may enter bounded queues
before redundant full-witness publication. Authoritative release, votes and root
confirmation still wait for the durable body and applicable exact consensus
journal ACKs. Queue eligibility does not prove peer delivery. Ax allocation and
signature releases retain their separate durable signer files.

The role registry is an immutable program-owned genesis account. Startup pins
the actual genesis hash, an independently trusted 48-byte activation-state
commitment, and the role keys, membership, stake and execution parameters.
Recovery reconstructs actual account state from pinned genesis and
the authenticated PQ journal. Classical snapshot loading is bypassed because
its hash is not a substitute for a PQ checkpoint certificate.

The [streaming pipeline](docs/native-streaming.md) separates production,
reconstruction, execution, ordered witness persistence and native archive
workers from the consensus coordinator. A same-leader successor can execute
on its exact frozen predecessor before that predecessor's full witness WAL,
network delivery, certificate and archive finish. Leader authorization adds
no fixed 500-ms delay; only underfilled work uses the bounded idle coalescing
interval. Complete payload selection still precedes streaming because the
current candidate identity commits that entire payload.

This is a separate experimental validator mode. It starts from genuine genesis
and accepts PQ transaction carriers. The eight-validator Rich-C experiment
executed ordinary Ed25519 application/token transactions, enrolled the same
addresses before cutoff, and continued with Falcon after the actual native Bank
cutoff. It does not import an existing classical ledger or implement a rolling
upgrade of an existing chain. That activation still needs a PQ-certified
checkpoint import and replay-version agreement. The signed rules currently bind genesis state and role parameters,
not a governed native ABI, VM version or executable build. Instruction ABI
changes, including the digest-bound INSTALL_LEGACY format, therefore require an
explicit compatibility plan for historical journal replay.

Membership and scheduling are static for one finite epoch. The initializer
defaults to 128 slots; the continuous-run implementation permits up to 18,000
disjoint Ax slots. The completed rich-state hour used a fresh
18,000-slot epoch. This does not implement rolling epochs. Reaching its end stops new block production; continuous epoch transitions are not wired
into the native validator. Used Ax state and its monotonic store must be retained
through restart, never reset to extend the same epoch. The transaction cutoff
is a trusted native Bank slot, not a UTC wall-clock deadline; production and
finality determine when that slot is reached. Profiles must therefore report
their actual slots relative to the configured cutoff.

The actual native QUIC/TLS profile uses Falcon CertificateVerify, pure
ML-KEM-768 key exchange, HKDF-SHA384 and AES-256-GCM. See
[`tls-utils/PQ.md`](../tls-utils/PQ.md) for its private wire profile and tests.
The final transaction, shred, consensus and TLS profiles are experimental and
require an explicit interoperable version and upgrade procedure. Native peers
load fixed 1,704-byte Falcon-authorized Ax root descriptors. They do not exchange
complete cached Ax public material: evidence carries the original inclusion
path. At 18,000 slots, a notar-vote frame is 1,997 bytes, comfortably below the
4 MiB QUIC frame bound; provisioning more keys does not send a multi-megabyte
material frame.

The Core path authenticates independent shreds and evidence and prepares erasure
batches on up to eight existing workers. Native SVM dependency waves also run in
bounded parallel batches; consensus decisions and Ax allocation remain ordered. A producer's already executed frozen Bank is reused only
through a private cache bound to chain, slot, parent, payload and full state;
followers and journal replay still execute the actual SVM. Outbound processing
reserves control and repair service before up to 2,048 bulk frames per peer.
Heavy production waits for the preceding local witness to enter bounded QUIC
queues covering at least 60% of stake, including the producer. That condition is
flow control, never a consensus certificate; a stalled minority retains retries.
The transport's byte and record bounds remain in force.

Native transaction/block history uses ordinary Blockstore archive and status
columns. PQ confirmation reads exact rooted identifiers, rather than the stock
status cache's truncated keys. The recovery journal appends incremental WAL
chunks; restart authenticates its original raw signatures and re-executes its
transactions. See [native data authentication](docs/native-data-auth.md) and
[journal persistence](docs/native-journal.md).

## Validation and reproduction

Fresh R30 singleton Verify at slot 1330 took **38.610–39.494 ms** across eight
warm whole native-Bank calls, at 1,006,151 CU and 1,008,161 transaction cost.
RPC-observed finality was **0.706942992 s** and the proof lifecycle
**111.614655975 s**. These separate intervals do not measure isolated verifier
CPU; fixed public-parameter prewarming does not cache proof acceptance.
[Actual proof timing](results/optimized-native-agave/profiling/pilot-r-main30-accepted-hour/README.md#warm-on-chain-proof-verification).

The actual modified `agave-validator` builds with:

```sh
cargo build --release -p agave-validator --features agave-unstable-api \
  --bin agave-validator --bin agave-pq-tool
```

`agave-pq-tool init` creates isolated genuine genesis files, vote/stake and
wallet accounts, role bindings and durable one-use signer state.
`tools/agave-cluster.py` manages only those owned validator processes.
`tools/resources.py` reports process CPU/RSS separately from shared host
network, disk and memory counters. Private keys and ledgers belong outside the
repository. Never reset an Ax signer to reuse its epoch keys.

The full private seed fixture has passed three real native SVM program tests:
53.079 ms for an initially absent authority, 55.594 ms for a program-owned
authority and 56.567 ms for a System authority, each charged 1,006,151 compute
units. The complete release run took 20.56 seconds including shared cold
preparation and uploads. The tests spent from the original address using the replacement Falcon
credential, rejected forged authorization and consumed-proof replay, and
refunded the upload while retaining the permanent policy. A debug run measured
1.142 seconds per verification and about nine minutes of cold preparation.

`prewarm_seed_verifier: true` prepares the locally derived universal verifier
before QUIC/RPC readiness is advertised. This shifts roughly 20 seconds of
release cold setup into startup on the measured hardware. It caches public
relation parameters, not accepted proofs or witness data; every VerifySeed
transaction still performs proof verification in native onchain execution.
Without prewarm, the first verification or recovered proof can incur that cold
setup. These setup, warm CPU and consensus-finality measurements are distinct.
During preserved-history Release 6 recovery, sampled RSS briefly reached
31–33 GiB at the first historical native VerifySeed, then fell after its
documented preprocessing trees were released. This is a cold verification
budget, separate from sustained validator RSS.
[Source and historical evidence](results/optimized-native-agave/owned-resource-census/release6-cold-proof/README.md).

The ten-validator run uploaded a 2,061,578-byte private proof in 252 write
transactions and completed 258 transactions including enrollment, same-address
Falcon spending and refund. Its VerifySeed transaction finalized in 1.115
seconds; the entire upload/migration sequence took 72.432 seconds. All ten
validators agreed on the policies and balances. After cold restart from the
same used signer state and journal, all ten reproduced the same 48-byte root
and served the exact verification receipt and block history.

An eight-validator/two-generator run finalized 10,000 transfers and continued
after a scheduled leader was killed before its window; restarting that node
reconstructed the actual native state. The v7 run used 32 payers and 64
recipients and finalized 50,000 transfers with matching balances on all eight
validators. It measured 3,177 TPS from controller launch to completion, or 3,524
TPS over the generators' reported wall interval. Exactly 50,000 transactions
were proposed, with no skipped blocks or alternative execution waste in that
run. These are finite native cluster bursts, not a sustained production ceiling.
Two fresh-genesis repeats of that 50,000-transfer workload on the same v7 binary
with a 100 ms interval instead of 250 ms measured 3,357–3,407 controller TPS and
3,773–3,802 TPS over generator intervals of 13.253 and 13.151 seconds. Each
proposed and committed exactly 50,000 transfers with no skipped alternatives;
within each run, all eight validators ended at slot 128 with the same 48-byte
state root and empty queues. The roughly 7–8% generator-interval improvement
does not establish a sustained maximum.
Historical standalone figures, including 7,396 TPS, are not Agave TPS. Public
evidence and measurement scopes live in [native results](results/native-agave/README.md).

The final 100 ms repetition completed its resource sampler, with samples before
submission and after completion on all eight nodes. During its generator load
window, most validators averaged 0.98–1.09 CPU cores on 128-logical-CPU hosts;
node 0 averaged 1.83 cores and peaked at 2.31 cores over a one-second interval.
Load-window RSS peaks were 1.96–2.13 GiB. Shared-host one-second peaks were
24–49 MB/s network RX, 24–99 MB/s TX, 45–291 MB/s disk writes and at most 5.4%
disk busy. These host totals include other workloads; they do not measure
PQ-only network or disk usage. The prior 250 ms run also sampled the actual
burst. The first 100 ms run's sampler did not complete, so it provides timing
and correctness evidence but no active-load resource claim.

Full 4,096-transaction proposals in the final repetition took 373–472 ms and
follower validation 244–295 ms. Serial SVM execution,
mandatory certified replay and repeated mempool normalization remain major
costs. A smaller configured block interval does not eliminate them. Reusing
immutable decoded intents and sanitized metadata is a future optimization, not
an implemented v7 path.

The historical v7 path retained candidate Banks and their strong ancestor
graphs; ordinary live-root pruning did not free private databases. Runs reaching
128 candidates observed about 894 threads and roughly 4 GB RSS. The continuous
implementation below detaches and reclaims those private graphs; reusable
AccountsDB workers and incremental account commitments remain future work.
The earlier small-genesis burst results do not establish mainnet-state capacity.

## Earlier continuous-run implementation

The earlier v7 figures above describe the source before the following changes.
The live service now syncs and releases staged journal buffers, authenticates
recovery in bounded chunks, and compacts recent consensus history only after
certified blocks have executed and rooted in the actual Bank. Raw authenticated
records remain in Blockstore, bounded at 256 GiB and 4,194,304 inputs. Earlier
release-2 and Rich-C runs used the previous 64 GiB cumulative limit. Metadata-only
journal usage reports stored body bytes/count/chunks without reading history;
recovery still validates and authenticates the full journal. Cold recovery
still verifies every raw witness and executes the native journal from genesis;
there is no compact snapshot trust shortcut.

That build's private Banks detach frozen parent Arcs and retain program ancestry as
immutable slot metadata. After full 48-byte private/live equality, the certified
ordinary live Bank replaces the rooted speculative Bank and retired private
Banks leave the live map. Actual tests deploy SBF in a private parent, detach it,
execute a descendant and compare live replay; a Weak reference proves the
retired parent is reclaimed. Replay-cache slot buckets use shared immutable
entries, and Core caches decoded transaction bodies and full-width canonical
intent identities. Durable Ax release verification uses a file-identity-checked
cache and indexed live retransmission, preserving fencing, burn, tamper and
rollback checks.

A 256-slot regression checks bounded history, a skipped leader window, delayed
and forged evidence, and complete authenticated streaming recovery. A 70,001-
record storage test exercises a journal beyond the previous 65,536-input bound.
The shared Quantumglow fault scenarios and native Core/Bank/SBF tests pass.
The completed native cluster experiment supplies separate sustained-traffic
and resource evidence below. Runtime validation now includes 25 native PQ
checks, one Merkle equivalence check and three complete private-seed tests; the
Tool's 12 tests, strict Clippy and exact CI nightly formatting also pass.

That build retained full parent account copying, full account Merkle calculation,
serial execution and mandatory certified replay. The optimized build below
replaces copying, serial execution and duplicate replay. Bounded admission can still be saturated by
far-future candidates, and a node far behind the live window needs a durable
checkpoint/certificate catch-up protocol. Journal reclamation and reusable
AccountsDB workers remain production requirements.

## Optimized native execution

The native PQ path now executes ordered, independent transaction waves through
bounded parallel Agave batches with native locks and SVM checks. Candidate
AccountsDBs write deltas over immutable, structurally shared parent snapshots.
Certification checks the cached execution capability and adopts the exact
frozen Bank; it does not execute the payload again. Synced native receipts and
confirmation publication follow state adoption. Parallel execution preserves
policy, ALT, ProgramData and loader dependencies, including charged CPI failure
rollback. The full SHA384 commitment framing remains unchanged.

Repair responses are bounded and coalesced; authenticated obsolete deferred
forks retire against the adopted root. Missing-parent discovery uses the durable
slot index instead of probing every slot in the finite epoch. Journal recovery
uses bounded sequential checksum scans before and after native replay, detecting
callback mutations without changing the ledger format or authentication.
Release 7 adds bounded causal repair priorities and exact re-fetch of evicted
full or partial witnesses. It keeps the existing capacities and requires the
same authentication and native execution checks before adoption.
Release 8 retains reload intent when queued repair bodies are evicted and their
recent copies later compacted; it also admits causal predecessors ahead of
unstarted lower-priority responses without resetting partial send cursors.
Its 34 applicable Core checks, strict Clippy, formatting and separate actual-genesis
native transfer test pass.

The initial visible-state map remains resident, and freezing still hashes the
entire account set. These costs, database worker creation and consensus/persistence
latency must be measured separately from the removed work. See
[account forks and promotion](docs/pq-cow-promotion.md),
[phase definitions](docs/native-profiling.md) and
[the optimized experiment workload and validation](results/optimized-native-agave/workload.md).

Release 8 completed a fixed 3,660-second mixed System/SPL run on eight native
validators and two dedicated generators: **19,827,921** successful transactions
at **5,411.09 TPS** over **3,664.313 seconds including observation and drain**.
Both actual admission spans exceed 3,659 seconds, with zero admission/execution
errors and complete draining. All eight native totals equal 606 prelude plus
these successes. Independent full account/fee/asset, 10,000-background-account,
process/profile, continuous ten-machine resource and cleanup checks pass.
Owned CPU means are 1.89–1.92 logical cores, RSS means 4.76–4.81 GiB with peak
6.25 GiB, and physical-write means 155–159 MB/s per validator. RSS continues to
grow and IO is bursty; the hour does not establish long-term retention stability.
[Accepted hour and resource plots](results/optimized-native-agave/profiling/hour-e/README.md),
[independent acceptance](results/optimized-native-agave/validation-release8/hour-e-independent-acceptance/README.md).

This fresh epoch's complete private RFC8032 seed proof also executed through
native onchain VerifySeed before load: 42.040–43.686 ms for the complete Bank
call on eight nodes, 1,006,151 CU and 0.705-second client-observed finality.
Prewarming fixed public parameters precedes readiness; proof acceptance is
still verified onchain. Offchain proving took 423.69 seconds and peaked at
339.38 GiB RAM, a separate setup budget.
[Fresh proof, migration and baseline](results/optimized-native-agave/fresh-epoch-prelude/README.md).

The prior frontend interruption exhausted its finite Ax epoch while idle;
those used histories remain preserved. A new epoch and detached owned workflow
completed this repeat, including authenticated continuation of its used state
after two pretraffic helper/model failures. All experimental processes are now
stopped and the ten original validators remain healthy.
[Durable workflow](results/optimized-native-agave/durable-workflow/hour-e/README.md).

## Earlier serial/copying continuous traffic

The earlier serial/copying build used eight actual Agave validators and two dedicated generators for a
3,660-second post-cutoff System/SPL traffic profile. Actual admission spans were
3,659.682 and 3,659.904 seconds, each exceeding one continuous hour. All eight
validators finalized 7,115,293 successful transactions with zero admission or
execution errors and exact recipient assets. The source interval including
drain measured **1,936.88 TPS**; native root-publication logs measured
**1,943.46 TPS** over their separately defined cross-clock interval. The frozen
hour used validator `be0833…`, generator `0e956…` and controller `4e425…`.
See the [hour evidence and charts](results/continuous-agave/hour-c/README.md)
for full hashes, denominators and per-node measurements.

The genesis included 10,000 nonzero-padded application states containing
20,480,000 data bytes. Their complete account records remained unchanged across
all eight validators during the hour. Rich migration had already exercised 33
same-address consent enrollments, 16 program-owned vaults, real PDA CPI,
multisig and sponsored Falcon rotation, and recovered private-seed authority
spending from its original PDA/SPL custody. The native VerifySeed transaction
finalized in **1.11885 seconds**, with exact **1,006,151 CU** receipts on all
eight validators. The [prelude](results/continuous-agave/rich-c-prelude/README.md)
retains the actual 323 migration, 259 private-seed and 20 shared-authority
transactions and intentional fee-charged CPI rollback outcomes.

| Hour resource | Per-validator mean or peak |
| --- | ---: |
| Owned process CPU | 1.05–2.70 logical cores mean; 4.28 maximum |
| Owned process RSS | 3.15–3.32 GiB mean; 4.18 GiB maximum |
| Owned physical writes | 53.65–54.28 MB/s mean |
| Shared-host network RX / TX | 6.98–7.75 / 6.65–7.07 MB/s mean |
| Shared-host disk busy | About 1.5% mean |

MB/s uses decimal bytes; GiB uses binary bytes. Network and host disk counters
include other workloads. One-second maxima and time series are retained in the
hour report; means do not describe the write bursts.

The hour exposed client observation starvation: a moving counter cursor could
keep scanning new arrivals without revisiting an old lookup that returned null.
Core already selects transactions through FIFO `mempool_order`; it did not use
hash-order scheduling. Joining 71,154 sampled IDs to native root logs placed
native generation-to-root below 7.49 seconds, despite source-observed tails up
to 131 seconds. This is a cross-host diagnostic, not a synchronized latency
benchmark. The opt-in client now completes finite high-water polling cycles,
uses four status workers with at most eight 256-ID jobs, and runs minute audits
separately. Every admitted identity and execution error remains reconciled.
The original synchronous client and its hour provenance are preserved.

With the same validator binary and offered 2,000 TPS per source, matched
120-second profiles with 8,192 outstanding slots per source measured 202,004
successes at **1,499.224 TPS** for the original client and 271,137 at
**2,093.302 TPS** for the fair pipelined client, a **39.63%** improvement.
The separate native root intervals measured **1,668.14 → 2,224.14 TPS**
(**33.33%**). Full-source observed latency maxima were 62.730 and 13.379
seconds; native sampled maxima were 6.439 and 7.468 seconds. A
separate 120-second pipelined trial offered 2,000/4,000/6,000/8,000 TPS per source
in 30-second phases with a 16,384 outstanding bound, committing 351,193 successes
at **2,728.878 TPS**. These short trials do not establish another sustained hour
or a production ceiling. Their new client/controller pins are `2ee113…` and
`2d9bdb…`; the native validator remained `be0833…`. See the
[matched client comparison](results/continuous-agave/client-comparison/README.md).

The final control audit covers all four source pairs: **7,939,627** successes,
exactly **39,698,135,000 lamports** of payer fees, and all 2,438 complete
protected records and 810 policies on every validator. Sixty-four finalized
receipts verify fixed 5,000-lamport fees and exact System/SPL/nonce lanes. An
initial expected-state audit failed on 2,040 rent-epoch fields; it is preserved.
The corrected predictor reads pinned native Rent (6,960 lamports/byte-year,
threshold 1) and predicts exactly 255 touched exempt System recipients per
validator normalizing from epoch zero to u64::MAX. No account or field is
excluded. See the [final custody audit](results/continuous-agave/account-audit-final/README.md).

## Remaining production requirements

- Independent review of the complete seed relation, STARK security parameters,
  Falcon implementation, Ax profile and consensus safety/liveness.
- Rolling epochs, governance, stake changes, key revocation and independently
  protected signer monotonic storage; the current consensus run has fixed
  membership and a bounded finite epoch.
- Import and activation of a live pre-PQ chain through a PQ-certified checkpoint,
  including snapshots, historical commitments, instruction replay versions and
  validator role migration.
- Migration of application-specific permits and custom classical cryptography.
- Final SDK/wire and hardware signing APIs, public client enrollment, production
  admission quotas, durable-nonce support and calibrated proof/signature fees.
- Mainnet-size incremental authenticated account state, reusable AccountsDB
  workers, scheduler integration and durable history reclamation.
- Longer sustained capacity at the improved client operating point, partitions,
  crash recovery, availability and Byzantine resource-pressure testing.
- Test longer matched durations and broader workloads beyond the completed
  same-Main30 ordinary reference. A modified-alpha comparison with classical
  signatures/default caps is not untouched production or pure crypto overhead.
