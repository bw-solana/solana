# Real SBF authorization fixtures

Both ELFs use the existing Agave example source at
`programs/sbf/c/src/move_funds/move_funds.c`. It checks account zero's signer
privilege and moves lamports from that program-owned account to account two.

`move_funds.so` is the existing SBPF v1 example, also used by core's PQ tests.
`move_funds_v3.so` was compiled for current deployment rules with platform-tools
v1.54, without deactivating any Agave feature. `sbpf_v3.ld` uses the strict
SBPF v3 ELF layout from solana-sbpf 0.24.0's `tests/elfs/elf.ld`.

Rebuild v3 from the repository root, setting `PQ_PLATFORM_TOOLS` to a local
platform-tools installation:

```sh
"$PQ_PLATFORM_TOOLS/llvm/bin/clang" -target sbpf -mcpu=v3 -Werror -O2 \
  -fno-builtin -std=c17 -DSOL_SBPFV3=1 -isystem programs/sbf/c/inc -fPIC \
  -c programs/sbf/c/src/move_funds/move_funds.c -o /tmp/agave-pq-move-v3.o
"$PQ_PLATFORM_TOOLS/llvm/bin/ld.lld" -z notext -static \
  -T runtime/tests/fixtures/pq-svm/sbpf_v3.ld --entry entrypoint \
  -L "$PQ_PLATFORM_TOOLS/llvm/lib/sbpfv3" /tmp/agave-pq-move-v3.o -lc \
  -o runtime/tests/fixtures/pq-svm/move_funds_v3.so
```

The deployment test executes the genuine UpgradeableLoader in a private Bank,
invokes the newly deployed program in a private descendant, then replays both
transactions into normal live Banks and compares the complete SHA384 state
commitments. The migration tests preserve an existing program-owned account's
owner and data while replacing its signer authentication with Falcon.

`workload.c` is a separate genuine SBPF v3 application, embedded by
`solana_runtime::pq_workload`. It creates a System-owned escrow PDA using
`invoke_signed`, stores application counters/authorities in a program-owned
account, deposits and withdraws through System CPI, enforces two signer
authorities for withdrawals/rotation, and deliberately fails after a successful
CPI to test transaction rollback. Its zero-account opcode carries a source and
counter nonce for repeatable constant-value load transactions.

Build it with the same compiler flags above, replacing the C input with
`runtime/tests/fixtures/pq-svm/workload.c`, the object with
`/tmp/agave-pq-workload-v3.o` and output with
`runtime/tests/fixtures/pq-svm/workload.so`. The Rust helper module defines its
complete account/instruction schemas. `program_accounts(&Rent)` installs both
the actual UpgradeableLoader program and immutable program-data accounts;
current deployment rules require this for the version 3 ELF. Enrollment
preserves existing program owner/data and post-cutoff Falcon signer privileges
propagate through the genuine VM and CPI dispatcher.
