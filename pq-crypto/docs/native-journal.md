# Native Agave recovery journal

The experimental Agave service persists authenticated Quantumglow input records
in its real RocksDB Blockstore before publishing the corresponding consensus
actions. The canonical recovery-record format remains version 1: a 53-byte
header (version, 48-byte configuration binding, record count), followed by
self-delimiting clock, Ax evidence, or Falcon-authenticated block-witness records.

The live service now asks Quantumglow only for records after its durable cursor.
This avoids cloning and encoding all historical shreds on each incoming vote or
clock tick. Blockstore checks the exact prior record count, immutable binding,
cumulative limits and existence of block witnesses for new roots. A synced WAL
batch contains the new record chunk, metadata and certified root entries; the
cached hash continuation and caller cursor advance only after that write succeeds.

Metadata `PQJNL003` uses a SHA384 stream with the fixed domain
`agave/pq/durable-recovery-journal-body/v2`. The 125-byte metadata layout and
existing chunk keys stay unchanged. Existing `PQJNL002` journals are read and
validated using their original length-framed checksum, then migrate to the new
checksum on the next append. A reopen verifies the complete body before caching
its continuation. Full-checkpoint callers remain supported, including prefix
rewrite and rollback rejection. Corrupt historical chunks fail validation.

The checksum protects storage integrity. Quantumglow recovery still decodes and
authenticates every original Ax/Falcon witness and re-executes actual Bank/SVM
transactions; a checksum never replaces those checks. Durable Ax allocation
state remains a separate rollback boundary.

## Journal ACK overlap in Main26 and later

One bounded worker appends one immutable canonical suffix while the coordinator waits for its exact sequence/header/prior-target-cursor/byte-extent ACK. No pending-transition actions, new admission, signing authorization or promotion escape before that ACK. The wait may service existing signed streams under their already durable payload intents; previously authorized worker jobs can finish. It does not poll the authoritative pipeline or dequeue more inbound work. Both own-vote ACK gates remain. Disconnect, storage, service and context errors fail stop without becoming rejected-peer input; successful-ACK cancellation alone maps to clean shutdown.

Main28 uses the existing journal accumulator mutex for both full and incremental journal writes from metadata lookup through synced write/cache advancement. Independent body/intent insertion retains its existing immutable-key lock. The raw native SHA384 backend preserves both metadata versions' domains/framing, complete48-byte digests, clone continuation, cold validation and reopen. Canonical append-to-buffer encoding removes temporary per-shred vectors without changing journal bytes, bounds or replay authentication. None of these changes removes required durability, history validation, device contention or the owner's suffix encoding/ACK wait. [Release-by-release implementation](native-overlap-main24-to30.md).

## Verification

The crypto delta test includes a genuine Falcon-signed block and checks that
concatenated updates reproduce the full canonical journal exactly. Ledger tests
cover legacy migration, reopen/append, stale cursors, changed bindings, missing
root witnesses, full-prefix rewrites, corrupt historic chunks and native RPC
history surviving a reopen. Core tests exercise actual default-feature Bank/SVM
execution and state-writing SBF, including private/live state equality.

The reproducible storage-only A/B test is:

```sh
cargo test -p solana-ledger \
  --features agave-unstable-api,dev-context-only-utils \
  benchmark_experimental_pq_incremental_journal_storage --lib \
  -- --ignored --nocapture
```

It starts with 8 MiB of opaque historical record bytes and performs 100 nine-byte
updates. Repeat with `cargo test --release` to use the optimized build. On the
current development host, measured totals were:

| Build | Full-history checksums | Incremental append | Ratio |
| --- | ---: | ---: | ---: |
| Optimized release | 5,072.349 ms | 8.010 ms | 633.26× |
| Debug | 187,941.743 ms | 14.893 ms | 12,619.43× |

Both journals were reconstructed and compared afterward. The historical setup
write is outside the timed loop. These are **storage checksum/append** timings,
not cryptographic-verification timings, transaction throughput or cluster TPS.
The large debug ratio reflects unoptimized SHA384 code and should not describe
production performance. Historical bytes in this microbenchmark are deliberately
opaque to isolate storage work; authentication and SVM execution are covered
separately. The optimized run's output is available in
`/tmp/agave-pq-incremental-journal-bench-release.log`.

The native service releases staged record buffers only after their synced WAL
append. Cold startup first validates the entire streaming checksum, then
re-authenticates records and replays/roots each certified native block before
advancing. Both passes validate the durable metadata/body; QUIC starts only
after successful replay. The current service uses bounded 64 MiB chunks with a cumulative
256 GiB/4,194,304-record limit, and tests exercise 70,001 canonical clock records
through reopen and append. Release 2 and the earlier completed hour used the
previous 64 GiB cumulative budget; raising it preserves metadata framing,
checksums, per-chunk limits and record-count limits. Legacy full-history convenience APIs retain their
smaller allocation limits; native startup uses the streaming visitor.

`Blockstore::experimental_pq_journal_usage()` reads only the stored 125-byte
metadata and validates its version, framing and byte/record/chunk bounds. The
reported body bytes, records and chunks are diagnostics. It never scans history,
verifies its checksum, authenticates witnesses or authorizes roots. Streaming
recovery continues to validate the full durable body before invoking its replay
visitor. Tests corrupt an actual historical chunk to demonstrate this separation
and reject 256 GiB + 1 declared bytes before any body/visitor work.

Budget planning must use actual retained record bytes. Native block records
retain data shreds with their authentication paths and signatures; generated
parity is not retained or disseminated on the current reliable QUIC path. A
matched rich-state sample encoded 856,231,571 block-record bytes for 475,397
transactions (1,801.09 bytes/transaction, approximately 1.61 times the raw
transaction payload). At 10,000 TPS for 3,660 seconds that sample projects
61.39 GiB before other consensus records, migration preparation and shorter load
trials. This is a workload-specific forecast, not a fixed amplification factor
or capacity measurement. Live metadata growth must confirm the hour's chosen
operating point. The 256 GiB budget provides finite experiment headroom; journal
reclamation, compact authenticated checkpoints and recovery-cost limits remain
required design work.

Recent in-memory consensus bodies may compact after actual rooted 48-byte state
verification, but raw witnesses remain durable. Journal reclamation, compact
PQ-certified checkpoints and far-behind certificate catch-up remain future work.

## Sustained native execution evidence

The [completed eight-validator hour](../results/continuous-agave/hour-c/README.md)
committed 7,115,293 post-cutoff System/SPL transactions with zero admission or
execution errors, exact native counts/assets and full resource coverage. Its
journal buffers and consensus histories used the bounded streaming/compaction
path above; original raw authentication remains durable. Background inventory
retained all 10,000 padded accounts and 20,480,000 data bytes across all eight.
Subsequent matched client/rate trials used the same validator binary, with the
[final control audit](../results/continuous-agave/account-audit-final/README.md)
reconciling 7,939,627 source successes and every protected account field.

This sustained run does not establish compact-checkpoint trust, journal
reclamation or cold recovery of the complete hour. Separate ten-node cold
journal tests and streaming regressions cover their stated shorter histories.
Long-journal crash recovery and far-behind catch-up remain distinct validation
requirements. Source status-observation delay also does not measure WAL/root
latency; see [profiling scopes](native-profiling.md).
