`move_funds.so` is the existing Agave C SBF example built from
`programs/sbf/c/src/move_funds/move_funds.c`. The fixture executes the real SBF
VM: a signed, program-owned account transfers lamports to its third account.
It is used to check PQ transaction authorization, private candidate execution,
and certified replay through the ordinary runtime Bank and program cache.

The checked-in ELF uses SBPF v1. Rebuild with the repository SBF examples build
workflow and copy `programs/sbf/target/deploy/move_funds.so` here.
