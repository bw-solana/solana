# PQ account forks and executed Bank promotion

The PQ coordinator now publishes the frozen Agave Bank that executed the
certified candidate. It does not execute the transactions a second time and
does not copy every account into each candidate database.

## Account state

AccountsDB's ordinary storage and cache identify versions by protocol slot.
`BankId` fences scans and purges; it does not isolate two concurrent versions of
the same slot. Sharing the ordinary writable AccountsDB between same-slot PQ
candidates would therefore allow sibling state to overwrite each other.

Each PQ candidate instead uses an AccountsDB write overlay and an immutable
parent account snapshot. The snapshot uses the workspace's persistent `imbl`
map. Cloning its root shares immutable nodes and account data. Native Bank/SVM
writes enter only the candidate's normal AccountsDB cache. At freeze, only
changed keys create new persistent map paths; untouched account values remain
shared. The initial frozen Bank builds its snapshot once.

Loads select the candidate's changed value before inherited state, including
zero-lamport tombstones. Filtering a changed account cannot reveal an older
inherited owner. Scans merge the exact candidate delta with untouched inherited
accounts, and owner/token secondary-index queries use that merged view. The
account's modified slot and `Clock.slot` remain actual protocol slots.

The inherited view never falls through to a mutable canonical database. A
sibling remains unchanged when another branch is rooted, flushed, cleaned or
dropped. Detached candidates keep snapshot and ancestry metadata without
retaining every physical ancestor Bank.

## Certification and publication

The coordinator must validate the complete PQ certificate, payload binding,
execution capability and frozen state commitment before calling
`BankForks::promote_pq_candidate`. That API additionally verifies that the
candidate is frozen and extends the exact current root's slot, native hash and
48-byte PQ commitment. The overlay independently checks its recorded parent
commitment and the canonical storage root.

Promotion writes only the certified candidate's modified accounts to the
original AccountsDB, which existing persistence/background workers service.
It preserves the executed Bank's status/replay caches, program cache,
transaction counters, fees and frozen commitment. The same `Arc<Bank>` becomes
the published root. Cached transaction receipts belong to that original
execution; publication does not create them by running SVM again.

Core adopts certified state before writing its cached finalized receipts.
Only after the atomic, synced archive write succeeds does it advance the
confirmation cache and progress counters. An archive failure stops the
coordinator, retains the certified root and durable consensus witnesses, and
does not publish confirmation or compact repair history. A regression checks
both successful publication and failure after adoption.

The signed SHA384 account Merkle tree and complete Bank state commitment retain
their existing framing and 48-byte width. Account ownership, rent, rollback,
PDA derivation and CPI checks still execute in native Agave SVM. No consensus
state check is omitted to obtain the speedup.

## Verification and remaining work

Independent regressions cover same-slot sibling isolation, deleted/recreated
accounts, filtered ownership, merged owner scans, stale-parent rejection,
root advance plus flush/cleanup, and persistence of only changed accounts.
Native Bank tests check exact frozen-Arc adoption, unchanged transaction count
and signatures, and promotion of a previously executed winner descendant.
After actual canonical storage flush, its full account view and AccountsLtHash
must equal the adopted candidate. A serial SHA384 protocol oracle checks
commitments independently of the production hash implementation.

The existing native runtime tests also cover Falcon authentication, SBF
deployment across candidate ancestry, account-owner migration, PDAs,
`invoke_signed`, multisig and fee-charged CPI rollback, SPL custody, Vote/Stake,
ALT/v0 and funded nonce recovery.

Whole-state SHA384 hashing and canonical Merkle-tree construction still cost
O(number of visible accounts) per frozen Bank. The persistent view avoids
candidate copying, but its initial map costs memory proportional to live state.
Incremental Merkle commitments, pooled overlay infrastructure and integration
with all snapshot/restart/upgrade workflows require further validation. Passing
these tests does not establish production readiness or support arbitrary
existing-chain activation.
