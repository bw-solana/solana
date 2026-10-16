# Native overlap from Main24 to Main30

Main30 removes redundant parsing, encoding and coordination work while retaining one ordered consensus owner and one native execution per candidate. Private work may run before its parent is durable; authoritative consensus changes, new signing and promotion still wait for their exact prerequisites. These changes introduce neither another SVM execution loop nor a full account-state copy. Required owned journal and wire buffers remain.

Main24 is the baseline for this description. It already starts bounded private received children before parent body WAL, prepares a same-leader unsigned successor before parent intent/sealing completes, and queues a sealed terminal after the synced exact payload intent without waiting for redundant full-witness publication. Those earlier changes remain. Underfull or empty work uses the configured **500-ms idle/coalescing interval**; full-ready work bypasses it. This producer policy is not an added 500-ms consensus or leader-handoff timer. Version-one selection/execution must still close the complete payload before the first signed DATA, and same-leader signing still requires exact accepted parent/authorization and used-slot/recovery fences.

## Implementation changes

| Release | Work removed or overlapped | Invariant retained |
| --- | --- | --- |
| Main25 | Borrow the current Quantumglow input during synchronous apply and move it into the raw journal afterward. Compute validated encoded lengths without allocating a temporary wire. | Same input/action order, structure/error bounds and canonical raw journal bytes; replay still authenticates the originals. |
| Main26 | One bounded journal worker owns an immutable suffix and appends it while already authorized outbound streams and existing worker jobs can progress. Durable encoders append canonical shreds directly into their owned buffer instead of making a temporary vector per shred. | The coordinator does not return from the semantic barrier until its exact ACK. No new receive/admission/QG transition, signing authorization, producer/native dispatch, compaction or promotion is released from the pending transition. |
| Main27 | Exact full-48-byte finalized-membership index replaces repeated linear history membership tests. | It mirrors the existing vector's lifetime and restored state, including compacted-anchor semantics. It is an index, not a checkpoint or additional evidence authority. |
| Main28 | A reused prepared candidate avoids a discarded full-mempool snapshot. A metadata FIFO readiness probe stops at the existing count/byte threshold; the original snapshot/selection path remains for other producers. Journal writes use their existing journal mutex rather than the unrelated global shred-insertion lock; storage SHA384 uses the native backend. | Exact parent Arc/state/profile/payload, fixed-intent precedence, sparse coalescing, shared capacity, immutable body/intent keys, synced journal roots/cursor and all historical checksum domains/framing remain. |
| Main29 | The existing authentication pool decodes canonical DATA shreds and verifies Ax evidence for the same collected batch of at most 256 frames. Completed-DATA apply consumes the decoded object instead of parsing it again. | No additional dequeue, queue or credits. The owner applies results in original arrival order and preserves evidence-group WAL boundaries, errors and current-state checks. Raw/recovery paths still verify. |
| Main30 | One best-effort thread-local entry remembers a successfully parsed canonical 666-byte public Falcon signature. Full-byte equality can avoid repeating the scalar encoding parser. | The new parse entry stores no mathematical verification, key/message/domain authorization or negative result. The pre-existing 65,536-entry positive exact-math cache remains downstream of fresh policy checks. Parse-cache borrow/TLS unavailability falls back to the unchanged parser; its thread-local storage is roughly 680 bytes per participating thread. |

The prepared evidence capability binds the exact pool instance, chain, epoch and slot interval, full membership/key commitments, and actual public-material cache identity/presence. The coordinator rechecks both prepared successes and failures. A changed context takes the original verification path, so a cached compact-proof success cannot survive loss of its required material and an old negative cannot suppress newly valid evidence. The owner still decides duplicate, equivocation, bounds, journal and action effects in order.

The existing bounded mathematical cache binds the full key, chain, domain, complete framed canonical message and actual signature, and skips only previously successful vendor mathematics after current Bank policy checks. A cache miss or eviction can require vendor verification again. Fresh authorization still runs, so “verification runs again” does not mean vendor mathematics always runs again. Newly admitted candidate DATA still requires the original Merkle, scheduled-leader, chain and context authentication; already-completed or known duplicates can take the existing early-return paths. Transactions reaching native execution still need current Bank policy checks under account locks.

The Falcon entry is only a public canonical-encoding shortcut. A warm entry cannot authorize another chain, message, domain or signer. The active controls cover canonical byte/error equivalence, full-byte misses, borrow conflicts and separate threads; TLS destruction fallback is structural and was not a directly exercised teardown control. Separate warm-repeat and alternating-miss microbenchmarks describe parser cost only, with their own instrumentation qualifications. They establish no fleet hit rate or TPS gain.

## Durable ordering

An append job contains one exact header, prior/target cursor, owned canonical suffix and finalized references. The ACK must match the barrier sequence, header, counts and byte extent before the owner discards durable in-memory records or releases actions. Ready ACKs wake immediately; the bounded wait interval is for continued stream service, not a mandatory delay per append. Worker disconnects, wrong ACKs, storage rejection and stream-service failures are fatal at the outer receive boundary and retain the original cause. Shutdown is clean only for the dedicated successful-ACK-plus-exit result; a real error during exit stays fatal.

During an ACK wait, `service_journal_wait` drains and advances only streams already owned by a producer reservation or exact pending publication under their durable intent. It does not poll the authoritative pipeline or admit another input. Existing native/archive workers may finish their already authorized jobs, including their original promotion behavior; no new authorization is taken from the unacknowledged transition. Both own-vote durability boundaries remain: persist the semantic intent before Ax signing, then persist the received own evidence before broadcasting/releasing its actions.

Blockstore full and incremental journal writes share the journal accumulator mutex from metadata read through `write_sync` and cache update. Independent body/local-body/proposal-intent keys keep their original guarded immutable-write rules. A journal root still requires its durable witness. SHA384's `PQJNL002`/`PQJNL003` metadata layouts, domains, framing, clone continuation, cold validation and reopen behavior are unchanged. This permits independent writes to overlap; RocksDB and the device can still serialize work internally.

## Remaining serial work and limits

Quantumglow mutation and arrival-ordered admission/actions still have one coordinator. It synchronously encodes each journal suffix before dispatch and waits for the exact durable ACK. A blocked ACK does not start new authentication for later inbound work; the next possible overlap is preauthenticating the same already collected batch before that wait, with unchanged credits and current-context rechecks. That change is not implemented here. Ax intent reconciliation/signing, required authoritative acceptance/root ordering, parts of candidate selection, repairs, compaction and native/archive handling also remain on the critical path. The new worker and caches do not remove every serialization point.

Full native parent availability and valid authorization remain required before authoritative child publication/consensus effects. Account-dependency execution, exact complete-payload identity, durable proposal intents, ordered certified promotion and receipt durability remain causal gates. The shared Bank/stream/peer/evidence/mempool bounds are not raised. A finalized-membership index can reduce repeated work; it does not guarantee catch-up under hostile future certificates, unavailable bodies or saturated bounded queues. The 64 MiB retained evidence pool can still fail closed when exhausted. Finite Ax allocation/epoch rollover, authenticated compact checkpoints, history reclamation and long-recovery budgets remain separate design work.

The [Clock and runtime compatibility gaps](runtime-coverage.md) remain: native Unix time can lag wall time, and AUTH-first transactions do not gain stock AdvanceNonce-first durable-nonce lifetimes. The workload's SBF uniqueness instruction supplies intent bytes without a state counter or Clock read. General application complexity, durable acknowledged-ID expiry/cancellation and general migration-client checkpoint recovery are not established. A finalized blockhash comes from a certified shared native Bank, not a private prediction, but a response does not prove that Bank's receipt archive has completed. The unresolved Q27 IDs have no proven hash-expiry cause without their exact signed-wire/hash/parent-queue join.

This remains a modified experimental alpha path. Independent cryptographic/side-channel review, key lifecycle and rollback analysis, private PQ transport interoperability, broader application/RPC coverage and hostile sustained-network testing remain required. Public-signature parsing reuse, storage checksums and prepared capabilities do not replace authentication, protocol review or safety proofs.

## Source and validation scope

The eight changed files against Main24-v2 are [Core owner](../../core/src/experimental_pq.rs), [worker pipeline](../../core/src/experimental_pq_pipeline.rs), [Blockstore](../../ledger/src/blockstore.rs), [Ledger tests](../../ledger/src/blockstore/tests.rs), [consensus](../src/consensus.rs), [crypto](../src/crypto.rs), [wire encoding](../src/network.rs) and [Quantumglow](../src/quantumglow.rs). The exact Main30 source/binary manifests bind 216 unique functional tests, three separately executed release microbenchmarks, strict lint, formatting, optimized builds and actual R-genesis compatibility. [Functional validation](../results/optimized-native-agave/validation-release30/native-overlap-and-parallel-auth/README.md) establishes the tested implementation; cluster acceptance and isolated performance attribution have separate evidence. Concurrency controls hold real WAL/ACK boundaries, compare complete native state/fees/receipts and raw action/journal/replay results, and exercise failure/recovery. Pure work counters and microbenchmarks are distinct from cluster results.

## Measured R30 results

All three PQ points passed their source/native-state/fee/background/resource gates and final cleanup. All eight stopped logs were captured. The [R30 report](../results/optimized-native-agave/profiling/pilot-r-main30-accepted-hour/README.md) contains per-machine resources, distributions and hash-only provenance.

| Accepted point | Configured target, total | Traffic duration | Successful transactions | TPS including drain |
| --- | ---: | ---: | ---: | ---: |
| R30 matched | 16,000/s | 120 s | 1,524,533 | 10,985.9625 |
| R30 pressure | 32,000/s | 120 s | 1,737,733 | 12,918.8914 |
| R30 hour | 8,000/s | 3,660 s | 29,275,165 | 7,996.5247 |
| Same-Main30 ordinary reference | 16,000/s | 600 s | 9,600,000 | 15,995.0415 |

The PQ generators are bounded and backpressured: the configured short targets were not all injected. Admitted counts divided by the nominal traffic interval were 12,704.44/s matched, 14,481.11/s pressure and 7,998.68/s during the hour; the table's TPS also includes drain. Ordinary met its 16,000/s target for all 600 seconds.

Every PQ load ID was observed finalized at its source. PQ acceptance reconciles all eight native slot/count histories and complete account, balance, fee and background-state oracles. It does **not** retain exhaustive per-load-ID status vectors on every validator. The ordinary reference additionally checked all 9.6 million source signatures on all eight replicas. The separate PQ 607-transaction migration/recovery prelude has complete full-64-byte-signature archives on all eight: 587 successes and 20 deliberate charged failures. All PQ validators ended at 32,538,038 native transactions including the prelude and both shorts.

Source 0 sends System transfers and source 1 SPL transfers, with 256 active payers each. Each PQ load transaction requests 20k CU and uses a 17-byte SBF uniqueness instruction, a transfer and the PQ AUTH instruction. It does not write an account counter or exercise stock durable-nonce accounts; this simple transfer workload does not represent general application complexity. Requested CU is not measured consumed CU. Pressure permits 131,072 outstanding IDs per source; matched/hour permit 32,768. Source-observed latency begins after signing, before source Job queue try_send, and ends when the source processes the exact ID as finalized; it includes queueing, transport, admission, consensus and polling.

Resources are weighted over each actual common offer interval, while throughput includes drain. Their division is a cost proxy. Host network/disk includes original services; summed process RSS peaks need not be simultaneous. Current PQ raw transaction-wire sizes remain unmeasured. R30 bundles changes and halves the Q27 hour offer from 16k to 8k total, so completion does not isolate a fix, peak-throughput gain or general efficiency improvement. Earlier rejected attempts remain rejected.

### One exact pressure handoff

The same observed pair throughout is slot 3312 (node 3) → 3313 (node 4), at 840.209 ms Ready spacing. It is the nearest actual lower neighbor of the 58-pair, 852.170 ms median, rather than a synthetic sum of median phases. Offsets are from the old leader's Ready; events on node 4 retain the cross-host wall-clock offset.

| Successor event | Offset from old Ready |
| --- | ---: |
| Parent reconstructed | 187.745 ms |
| Parent candidate dispatched | 193.364 ms |
| Parent native capability observed | 417.042 ms |
| Child unsigned preparation dispatched | 496.438 ms |
| Parent body durable | 507.051 ms |
| Exact parent authorized | 582.500 ms |
| Child unsigned preparation ready | 725.670 ms |
| Child producer dispatched | 748.393 ms |
| Child Ready | 840.209 ms |

The 79.396 ms native-observed→unsigned-dispatch interval remains unassigned owner/work/queue time. The 22.723 ms preparation-ready→producer-dispatch gap is observed but has no isolated causal attribution. The 90.009 ms native-observed→body-durable interval contains a 10.550 ms body DB call; it is not 90 ms of DB time. Child unsigned preparation begins before body durability and authorization and still has 143.170 ms to run after authorization. Worker-start→Ready is 91.813 ms, with 68.958 ms authorized sealing and its nested 34.337 ms intent stage. Do not add these nested observations into another timeline.

Full48 identity joins support these event pairings. Finalized membership means the checked all-eight slot/count census, not reconstructed certificates. Native-capability observation includes coordinator pickup, and max(native capability, authorization) is only a partial prerequisite. No hashless journal ACK or last-observed DATA endpoint is assigned to this block as a network-only or last-required-arrival timer. Prepared reuse occurs in 230/233 loaded committed pressure blocks (98.7%); the lower, underfull hour operating point is a different cohort. The hour's observed same-leader Ready-spacing median is 728.738 ms under that 500-ms underfull policy; it must not be read as a mandatory handoff delay or attributed wholly to one timer.

### Warm on-chain Verify

Fresh R30 Verify executes in 38.610–39.494 ms across the eight warm native Bank calls, charging 1,006,151 CU and 1,008,161 transaction cost. RPC-observed finality is 0.706942992 s and the proof lifecycle is 111.614655975 s. These are separate scopes; isolated cryptographic CPU is unmeasured. [Actual proof evidence](../results/optimized-native-agave/profiling/pilot-r-main30-accepted-hour/README.md#warm-on-chain-proof-verification).

The [ordinary reference](../results/optimized-native-agave/profiling/ordinary-main30-vs-pq-r30/README.md) passed both owners, all 14 workflow phases, full audits and cleanup: 9.6 million successful transactions at 15,995.0415 TPS including drain over 600.186 seconds. It uses the same modified Main30 binary without PQ configuration, this branch's native Alpenglow development configuration with BLS voting, Ed25519 transactions and native default caps. Its manifest records `alpenglow_default_development_genesis=true` and `poh_hashes_per_tick=null`; readiness checked native BLS votes. Its 600-second configured 16k/s-total target matches the target of the 120-second PQ matched point; pressure and the 8k/s-total hour are separate operating points. It is not untouched production, a hardware ceiling or pure cryptographic overhead. Historical Main19 ordinary evidence remains labeled Main19.
