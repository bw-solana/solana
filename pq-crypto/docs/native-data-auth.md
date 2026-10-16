# Native Agave block authentication workers

The experimental Agave Core service uses a bounded worker pool of one to eight
threads for Falcon/Merkle shred authentication and Reed–Solomon reconstruction.
The worker count is capped by the host's available parallelism. A receive batch
contains at most 256 frames and stops after reaching 4 MiB; a final frame can
extend that batch by at most the transport's 4 MiB frame limit.

Shreds are grouped by slot and candidate for signature reuse and independent
inclusion-proof checks. Individual authentication calls contain at most 128
shreds. Authentication workers produce private `VerifiedShred` capabilities;
they never mutate the consensus machine, AccountsDB, Ax allocation state or
RocksDB. Core inserts authenticated shreds and processes other frames and errors
in original arrival order. The scheduled leader, chain, epoch, candidate and
parent bindings are checked again when a capability enters its assembler.

A malformed initial shred cannot select the parent for later valid shreds in
the same group. Completed candidate buffers retain only their assembler's raw
authenticated witnesses, removing the former duplicate receive-vector copy.

After a terminal marker arrives, `try_finish_verified` performs complete
authentication and reconstruction once. Incomplete candidates return their
partially populated assembler for later frames. Successful candidates carry
private chain/key/marker/shred/payload fields into Quantumglow's
`observe_verified`; callers cannot replace those fields or authorize a different
leader. This avoids running the same erasure recovery and inclusion checks a
second time during live consensus admission.

On the producer, independent data/parity/Merkle batches are prepared in parallel.
Their signatures and previous-batch commitments are sealed in order, preserving
the authenticated chain. Actual Bank/SVM execution and Ax signing decisions
remain ordered. Canonical recovery journals persist the original raw witnesses;
restore always authenticates them completely and re-executes Bank/SVM state.

Core tests exercise one, four and eight workers, a malformed first context,
authentication batches larger than 128 shreds, partial candidate retention,
ordered insertion and exact payload recovery. A crypto regression compares the
raw and verified live journals, restores the original raw journal and rejects a
modified shred during restore. Actual state-writing SBF and certified/live
Bank-state equality tests remain part of the Core suite.

The earlier receipt bug was independent of execution: the generic ledger
earliest-slot search used classical shred counters, treating PQ archives as
empty and moving the transaction-history search lower bound to the current
root. Native archives now count as populated blocks. The regression checks an
older transaction after a later empty root and after reopening the ledger.

PQ ingress duplicate suppression, proposer branch deferral and finalized
mempool cleanup use the Bank's exact canonical 48-byte committed-intent cache.
They do not use the native legacy status cache's twenty-byte signature slice.
Core regressions inject a false positive into that native cache, then execute
the still-uncommitted PQ intent successfully on actual default-feature and
all-feature Bank/SVM configurations. Exact identities survive private branch
construction and actual journal re-execution. Native PQ RPC confirmation helpers
likewise use exact rooted 64-byte archive identifiers under the published root.
