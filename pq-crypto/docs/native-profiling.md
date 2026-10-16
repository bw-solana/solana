# Native block phase profiling

The native PQ implementation emits INFO summaries of the form
`PQ phases stage=... slot=... key=value`. Timings use monotonic `Instant` and are
reported in microseconds. There is no per-transaction logging, and profiling
does not authorize execution, change queue limits or replace state checks.

| Stage | Measurements | Scope |
| --- | --- | --- |
| `producer` | `private_child_us`, `native_execute_us`, `bridge_us`, `select_us`, `encode_us`, `freeze_us`, `payload_bind_us`, `prepare_us`, `freeze_prepare_us`, `seal_us`, `seal_sign_us`, `frame_encode_us`, `stream_queue_wait_us`, `terminal_us`, `capability_us`, `persist_publish_us`, `total_us` | Local production of one exact authenticated payload. |
| `candidate` | `decode_us`, `private_child_us`, `native_execute_us`, `bridge_us`, `freeze_us`, `capability_us`, `total_us` | Actual execution of a newly received candidate. A valid locally executed capability avoids this second execution. |
| `receive` | `authentication_us`, `reconstruction_us`, `observe_us`, `block_wal_us`, `journal_wal_us`, `observe_persist_us`, `consensus_observe_us`, `coordinator_install_us`, `coordinator_receive_us` | Stateless Falcon/Merkle verification, parallel batch reconstruction, then ordered consensus/execution and durable publication. |
| `finalize` | `promotion_us`, `archive_wal_us`, `root_publish_us`, `mempool_prune_us`, `duplicate_execution_count`, `total_us` | Adopt the exact frozen candidate, persist cached native receipts, then publish confirmation. No second SVM execution. |

In the optimized native build, `private_child_us` measures construction of a
native AccountsDB write overlay over a structurally shared, immutable parent
snapshot. It no longer scans/copies the full parent account set or rebuilds its
commitment. `freeze_us` includes tick completion, normal Bank freeze and the
full SHA384 account-state commitment. Subsequent commitment lookups are cached.

`native_execute_us` is the sum of the maximum native worker-call duration in
each ordered wave. Native workers call
`Bank::load_execute_and_commit_transactions` with real sanitized batches and
native account locks. It estimates the native execution critical path;
`native_worker_us` sums all native worker durations and is not wall time.
`parallel_waves`, `max_parallel_transactions` and `peak_active_batches` record
the actual execution shape. `bridge_us` covers surrounding sanitization,
dependency resolution, cost reservation/refund and receipt metadata work.
`select_us` is the remaining producer selection work. Threads preserve FIFO
write dependencies, policy reads, lookup-table resolution and loader barriers.

The streaming build reports preparation and erasure coding as overlapping
work. `freeze_prepare_us` is their joined wall interval; `freeze_us` and
`prepare_us` are nested worker intervals. `producer_phase_overlap_us` records
their overlap. `seal_us` includes Falcon signing, frame encoding and waiting
for the bounded coordinator stream queue. Its three nested timers separate
those costs; a long `seal_us` alone does not establish slow Falcon signing.

The native executor also separates serial transaction preparation
(`native_prepare_us`), dependency discovery (`native_access_discovery_us`),
cost reservation (`native_cost_reserve_us`) and receipt reconciliation
(`native_reconcile_us`). `native_pool_dispatch_join_us` includes execution;
`native_pool_overhead_us` subtracts each wave's longest native call. The latter
still includes parallel account locking, balance reads and framing. Neither
`bridge_us` nor its residual is an exclusively serial CPU measurement.

The serial fields `decode_us`, `live_child_us`, `native_execute_us`, `bridge_us`
and `freeze_us` remain in finalization rows with value zero, alongside
`duplicate_execution_count=0`, for comparison with older logs. These zeros do
not remove validation: the finalizer checks the certified payload, parent,
native transaction count and cached full 48-byte state commitment before
promoting the executed bank. Account delta persistence is part of promotion;
synced receipt persistence is measured separately.

The earlier continuous Rich-C build used serial
`Bank::process_transaction_with_metadata`, full parent copying and a second
serial execution at finalization. Its archived timing meanings remain those
of that build. Compare old/new native timers with their definitions, rather
than treating a parallel worker-duration sum as an old serial wall time.

Authentication and reconstruction accumulate across received groups for each
candidate; the instrumentation map is bounded independently and cannot reject
packets. Those earlier measurements exclude time spent waiting for network
data. `observe_us` includes native candidate execution when required;
`observe_persist_us` starts at that observation and excludes the earlier crypto
work. In the earlier layout, the `candidate` row nested inside a follower's `receive`
row and producer publication nested another `receive` row. Main30 private replay,
body writing and descendant work can overlap. Join full48 identities and exact
roles rather than adjacent dispatch rows; do not add nested stage totals.

In the streaming build, the older `observe_us` and `observe_persist_us` can
also include worker queueing and complete witness WAL persistence. Use
`consensus_observe_us` for the cached Quantumglow observation call and
`coordinator_install_us` for local metadata installation.
`coordinator_receive_us` covers their coordinator call, including journal
persistence. These nested measurements do not isolate network RTT.

Once per second, `PQ coordinator` reports actual window duration, turn count,
active wall time and the longest active turn. Its nine disjoint phase sums
and maxima cover ingress, frame collection, pipeline results, received batches,
consensus tick/persistence/actions, compaction, production dispatch, outbound
stream work and retry/status work. Production dispatch sums the early call
after worker-result polling and the later call after consensus actions; these
are disjoint calls, not an extra producer execution. Pipeline polling also
services ready deferred candidates without waiting for the repair timer. The deliberate one-millisecond loop sleep
is outside active time. Underfull/empty production also uses the configured
500-ms idle/coalescing interval, which full-ready work bypasses; it is not a
fixed leader-authorization delay. Dispatch logs report ready entries and the remaining
idle coalescing interval. These measurements distinguish a busy coordinator
from an underfilled producer or unavailable authorized parent; they are not
per-thread CPU counters.

Block-WAL and archive-WAL measurements include serialization and synced
RocksDB calls. They do not isolate physical device write time, asynchronous
AccountsDB flushes or every Ax-signing WAL operation. Compare them with process
and host I/O samples. Root publication and private reclamation can also invoke
native cleanup outside the measured SVM call.

Main30 emits `PQ ledger stage=write` for new `body`, `local_body`, `intent` and
`journal` writes. Journal `lock_wait_us` measures acquisition of the dedicated
journal writer/accumulator mutex. Body and intent writes retain the separate
insertion mutex. `prepare_us` begins after the relevant mutex is acquired;
`write_sync_us` is the RocksDB database-call wall interval, not isolated device
or fsync-syscall time. `total_us` covers the method. These intervals nest with
producer/publisher/coordinator work. Logical bytes are not physical writes;
integer zero mutex wait means below the observation precision. Idempotent no-op
writes do not emit a new-write sample.

`PQ pipeline stage=journal_ack` has a barrier and prior/target record cursor,
not a slot or block identity. `encode_us` runs on the owner before submission;
`queue_us` is worker pickup, `worker_append_us` the worker call, and `ack_wait_us`
the owner interval that can overlap restricted stream service and existing
workers. `service_turns` and `drained_stream_events` describe that service. Do not
invent a block join from an ACK row, add its nested wall times to coordinator
active wall, or interpret active wall as thread CPU. A ready ACK wakes immediately;
the bounded receive timeout for service is not a fixed one-ms journal delay.

Producer dispatch has two different snapshot scopes. A full snapshot reports
exact `eligible_entries`/`eligible_bytes` and deferred counts. A
`prepared_reuse_probe` reports a FIFO prefix and `*_lower_bound` values; it may
stop at the existing count/byte threshold. Keep those distributions separate,
including the scanned-prefix deferred count. Neither is an additional SVM loop.

Current full48 handoff joins require the exact terminal block/payload identity
and successor parent, and leave missing/ambiguous observations missing. Finalized
slot/count membership does not reconstruct a certificate. A native capability
row includes owner pickup; max(native capability, authorization) is an observed
partial prerequisite, not a complete handoff explanation. See the
[actual R30 case](../results/optimized-native-agave/profiling/pilot-r-main30-accepted-hour/README.md#one-pressure-handoff-using-the-same-pair-throughout).

`PQ transport stage=block_timing` supplies bounded boundary-block landmarks
for queueing, writer service, Quinn write completion, payload read and Core
dequeue. Public prefix metadata is unverified at transport inspection: join it
to an authenticated Core candidate using peer, direction, slot and complete
48-byte candidate identity. Repeated frames remain in the aggregates. Quinn
write completion establishes neither peer receipt nor QUIC acknowledgement.
Cross-host differences depend on clock alignment and do not isolate network
transit. Byte-budget reservation can wait before payload reading, so read-time
landmarks alone omit that delay.

RPC status also exposes cumulative inbound byte-budget and channel wait
counters, including maxima. Their sums overlap across asynchronous readers;
they are not exclusive elapsed time or process CPU. Compare pinned-process
deltas, queue occupancy, native progress and coordinator phase measurements.
The [release22 short analysis](../results/optimized-native-agave/profiling/pilot-n-main22-vs-m21-l19/timings/README.md)
preserves these distinctions. The later continuous attempt failed and cannot
serve as an accepted hour.

Compare populated blocks by transaction count and bytes, and compare empty
blocks separately: empty blocks expose state-copy/hash and persistence costs.
Report per-node/role medians and tails alongside throughput, balances, root
agreement and pending queues. The [completed hour](../results/continuous-agave/hour-c/README.md) supplies
separate actual rooted-count, asset and resource evidence. Phase timings alone
are not a sustained-throughput result.


## Comparable pilot profiles

Compare the same nonce-only SBF workload, transaction size, 20,480,000 bytes of
background state and 10,000 background accounts. Keep offered rate, outstanding
bounds, block cadence, source binary, validator binary and cutoff position in
the result. A pre-cutoff pilot can retain legacy status-cache entries in private
fork copies; a post-cutoff profile has different replay-cache work. The cutoff
uses the actual Bank slot, not elapsed UTC time. Finite provisioned Ax epochs
still stop at their configured slot count and do not roll over automatically.

Earlier profiles used at least 3,500 transactions for their near-full cohort.
Current R30 joins use at least 90% of the configured proposal-byte target or the
configured transaction limit; retain that exact frozen definition. Empty blocks
remain separate. Join producer/follower/finalization events by role, slot and
full48 block/payload/parent identity, excluding later migration/control blocks,
and reconcile counts against source success and all-eight finalized histories.
The Gen7 load has every-ID source-finalized observations and full all-eight
state/fee/count oracles, rather than exhaustive all-eight load-ID status vectors;
the 607-transaction prelude has complete full64-signature archives. Report
leader-window handoff gaps separately from gaps within a window. Bigger bounded
backlogs can fill more blocks but also increase finality latency, so pending
counts and admission gaps must accompany TPS.

The actual native Ax wire uses fixed 1,704-byte Falcon-authorized descriptors
and per-evidence inclusion proofs. Complete Ax public material is not exchanged
or installed by Core. For the current 18,000-slot experiment, the inclusion path has 19 SHA384
siblings:
39 header bytes + 67 message bytes + 26 key/path-header bytes + 912 proof bytes
+ 952 WOTS bytes = 1,996 evidence bytes, plus one frame tag. Larger finite epochs
therefore do not imply multi-megabyte material transfers on this implemented
path.

## Completed hour and source observation

The frozen eight-validator/two-generator hour finalized 7,115,293 successful
post-cutoff transactions with zero admission/execution errors. Both source
admission spans exceeded 3,600 seconds. Source completion including drain was
1,936.88 TPS; actual native root logs measured 1,943.46 TPS over their separately
defined cross-clock interval. Do not interchange those denominators or add
independent source minute curves as synchronized rates.

The source's `latency_ms` includes pending scans, status polling and audits.
Joining 71,154 approximately 1/100 sampled IDs/slots to node-zero root logs gave
estimated native generation-to-root means around 2.85 seconds, p95 around 5.42
seconds and maximum 7.49 seconds. None of the 384 sampled source observations
above 65 seconds required that long to root. The source-observed 131-second tail
included about 125.7 seconds of delayed observation. Cross-host wall clocks and
post-publication log work prevent treating that join as a synchronized latency
benchmark. Core's producer uses FIFO `mempool_order`; its full-width-key map is
for lookup, not hash-order selection.

The old status scanner advanced through a moving upper counter and wrapped only
when fewer than 256 eligible forward IDs remained. New arrivals could therefore
starve old null lookups. The opt-in client freezes each polling pass's high-water
counter, wraps after the finite pass, and uses four workers with at most eight
256-ID jobs plus a separate minute auditor. Exact identities, admission and
execution errors, and all final asset deltas remain checked. The original hour
used its unchanged client; the fix has separate source/binary provenance.

[Matched client trials](../results/continuous-agave/client-comparison/README.md)
used the same frozen native validator and System/SPL workload. At 2,000 offered
TPS per source and 8,192 pending/source, the original 120-second profile committed
202,004 transactions at 1,499.224 TPS; the fair pipelined profile committed
271,137 at 2,093.302 TPS (+39.63%). The separately defined native root intervals
measured 1,668.14 and 2,224.14 TPS (+33.33%). Full-source observed maxima fell
from 62.730 to 13.379 seconds; the fair profile's sampled maximum was 13.321
seconds. Sampled native-root maxima were 6.439 and 7.468 seconds.
More completed work does not imply lower native-consensus latency: sampled native
means rose from about 2.52–2.56 to 3.12–3.13 seconds as the pipeline filled more
blocks. A short higher-offered-rate trial committed 351,193 at 2,728.878 TPS.
These follow-up trials do not establish a second sustained hour or a production
ceiling, and do not replace a matched stock Agave end-to-end comparison.
