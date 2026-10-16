# Main30 implementation validation

Main30 passed **216 unique functional tests**, plus **three separately executed release microbenchmarks**, strict Clippy, formatting checks, the optimized validator/Aux build and the actual fresh R native-genesis compatibility case. All checks bind the same final 79-file source manifest. Runtime outcomes are reported separately.

| Functional component | Passed occurrences |
|---|---:|
| Crypto primitives |20|
| Core |104|
| Consensus |7|
| QuantumGlow |22|
| Network |21|
| Ledger |25|
| TLS |17|
| Actual fresh R native genesis |1|

These total 217 occurrences. One network-finality test appears in both QG/network filters, leaving 216 unique functional tests. The normally ignored native-genesis function was actually executed and is included in 216. A separate ignored ledger benchmark was not executed.

Main30 adds a bounded canonical Falcon encoding-parser cache: one successful full 666-byte entry per thread, with exact byte equality and the existing scalar fallback when the entry is unavailable. The new parse entry caches no authentication or mathematical-verification decision. The pre-existing bounded 65,536-entry positive exact-math cache remains after fresh transaction-specific Bank policy checks, keyed by the complete key, chain, domain, canonical message and signature; a miss or eviction can rerun vendor mathematics. The observed 64-bit TLS structure is 680 bytes; real thread-local destruction was not tested, and its access fallback is a source-level guarantee.

| Separate release microbenchmark | Actual wall result | Actual thread CPU result |
|---|---:|---:|
| Repeated identical canonical encoding: scalar / cached |4.6541×|4.3571×|
| Two alternating signatures, forcing misses: cached / scalar |1.02507×|1.02420×|
| Raw storage SHA384: Rust sha2 / OpenSSL stream |2.72681×|2.72330×|

Each benchmark alternated backend order over four trials. Parser tests used 20,000 calls per path per trial. The storage test hashed 13,476,746 payload bytes 80 times per backend from cloned common-domain prefixes, with all 48 digest bytes checked against independent Rust sha2 outside timers. Canonical outputs were checked across all 666 bytes outside timing. Forced-miss bookkeeping includes a test-only scalar-call counter; short CPU timing has finite resolution.

These measure raw storage hashing or canonical encoding parsing. They exclude verification/signing, database durability, network and native execution. No cluster throughput or whole-validator efficiency gain follows from them. File sync, directory sync, raw encoding and protocol semantics remain governed by the tested production paths.

The exact final source SHA384 manifest and hash-only evidence provenance are in summary.json. Inherited first/second receipt suffixes refer to checks run on the final THIRD source set. The final style/integration deltas were test-only. Earlier failed records remain preserved privately; this report replaces none of them.

[Implementation ordering and remaining limits](../../../../docs/native-overlap-main24-to30.md)
and [actual accepted R30 shorts/hour](../../profiling/pilot-r-main30-accepted-hour/README.md)
are separate from this source-validation report. PQ load evidence has every-ID
source-finalized observations plus all-eight state/fee/count oracles; exhaustive
all-eight per-load-ID status vectors are not claimed. The 607-transaction prelude
has complete all-eight full64-signature archives. The [ordinary same-Main30
reference](../../profiling/ordinary-main30-vs-pq-r30/README.md) also passed its full
workflow: 9.6 million successful transactions over 600 seconds of traffic, at
15,995.0415 TPS including drain, with every source signature checked on all eight
replicas. It uses native default caps and classical signatures; this does not establish
untouched production or isolated cryptographic overhead.

The final workspace matches all 79 files of the tested Main30 source manifest.
After integrating the eight changed files, package formatting with nightly and
strict Clippy for the changed libraries and tests passed again. The 216 functional
tests were run on that identical source set before integration. The separate
[workspace integration record](workspace-integration.json) binds these final
checks; it does not count the functional tests a second time.
