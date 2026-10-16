# Falcon implementation dispatch

The Agave PQ path uses `pqcrypto-falcon` 0.4.1's original Falcon padded512
implementation. Public keys remain 897 bytes, secret keys 1281 bytes,
and detached signatures exactly 666 bytes. Chain and role framing, canonical
coefficient validation, private credential serialization and Rust secret-buffer
zeroization are common to both backends.

On x86_64, dispatch selects the vendor AVX2 implementation only when the CPU and
operating system support every instruction set enabled by its build script:
AVX2, BMI1, BMI2, AES, POPCNT and PCLMULQDQ. Detection is cached once per process.
The vendor's floating-point multiply/add macros do not require FMA. Other CPUs
use the vendor CLEAN implementation. No environment variable overrides feature
detection, and no custom Falcon algorithm is introduced.

The backend test generates keys with each available implementation, persists and
reloads them, signs with both implementations, and verifies with both. It covers
all nine signature domains and empty, 256-byte and 64 KiB messages. Wrong keys,
signature nonces, chains, domains and messages are rejected by both verification
implementations. Separate tests preserve malformed encoding and message bounds.
Canonical bit decoding uses bounded byte windows; exhaustive boundary tests
compare it with a bit-by-bit reference reader.

The actual Bank comparison is recorded in
`../results/bank-bench-10000-64-a.json` (CLEAN) and
`../results/bank-bench-10000-64-avx2-a.json` (AVX2). Both ran on an AMD EPYC 9354,
with 64 logical CPUs, 64 signing threads, 64 wallets, and 10,000 successful
System Program transfers in forty bounded blocks. The AVX2 run precedes the
canonical bit-reader optimization. Its generation CPU cost fell from about
5,989 to 370 microseconds per transaction; total measured workload CPU fell
from about 6,164 to 544 microseconds per transaction. Wire sizes stayed 993 bytes
for PQ and 215 for Ed25519. These results describe actual Bank/SVM execution,
not network or consensus TPS. Early authentication and locked execution remained
serial in this comparison, and process peak RSS is cumulative across modes.

The final v2 account-state profile is measured in
`../results/bank-bench-10000-64-avx2-v2-b.json` and
`../results/bank-bench-1000-8-avx2-v2-a.json`; binary and source hashes are in
`../results/bank-bench-avx2-v2-provenance.json`. For the 10,000-transfer run:

| Actual Bank workload metric | Default Ed25519 | PQ Falcon |
| --- | ---: | ---: |
| Measured workload transactions/second | 18,999 | 6,127 |
| Generation CPU, microseconds/transaction | 99.8 | 368.5 |
| Early full authentication CPU, microseconds/transaction | 40.4 | 70.9 |
| Locked Bank/SVM CPU, microseconds/transaction | 9.3 | 85.3 |
| Ticks/freeze/root CPU, microseconds/transaction | 2.9 | 7.4 |
| Total measured CPU, microseconds/transaction | 153.6 | 533.4 |
| Mean transaction wire bytes | 215 | 993 |

PQ freeze includes computation of the canonical SHA384 account Merkle root.
The separately timed state-query field reads the cached commitment. All
transactions succeeded and both final recipient balances match their transfer
sums. The 1,000-transfer/eight-wallet run measured 18,914 default versus 6,084
PQ workload transactions/second. Neither result is a cluster capacity limit;
signature admission and Bank execution were intentionally serial while
generation used 64 threads. Different runs and processors vary.

Vendor implementations and this experimental fixed profile still require
independent cryptographic and protocol review before production use.

## Bounded transaction verification cache

Transaction-domain verification retains only successful vendor signature math.
Its SHA384 key commits the exact public key, chain, domain, complete framed
message and signature. Sixty-four shards retain at most 1,024 entries each;
failed verification is never inserted, duplicates do not increase storage, and
poisoned cache locks fall back to ordinary verification. Other signature domains
continue direct vendor verification.

Native admission and execution still read current account policies, and enforce
nonce, replay, fees, account locks and CU limits independently. The RPC regression
warms a signature, asserts a cache hit, retires its key in the actual Bank policy,
and confirms the queued transaction is rejected while the replacement key works.
Backend interoperability tests bypass the cache to exercise both implementations.

`../results/bank-bench-10000-64-cache-v2-a.json` repeats the real Bank workload
with 10,000 cache misses and 10,000 hits. It measured 6,745 PQ versus 17,724
default workload transactions/second. Locked Bank/SVM CPU fell from 85.3 to
55.6 microseconds per transaction; ingress verification misses gained the cache
key's hashing cost, measuring 83.1 microseconds. All balances and transaction
counts matched. This remains an offline Bank workload comparison, not cluster TPS.
