# WP9 interprocedural INTEGER-pair result evidence

Date: 2026-09-03

## Defect

`167_rust_trait_objects:rustc:O2:rust_dyn_apply` calls the internal Rust
function `choose`, which returns a trait-object fat pointer in the System V
INTEGER result pair `rax:rdx`. The caller immediately uses `rax` as the data
pointer and loads the method slot from `[rdx+0x18]`.

The scalar call model defined only `rax`. Consequently `rdx` became the
undefined local `var4`, and the final output dereferenced a value the original
machine never left undefined.

## Proof and change

`src/ir/interprocedural_return.rs` joins two independently insufficient facts:

1. A forward must-definition analysis proves both ABI result registers are
   defined on every reachable machine-return path through the callee.
2. A bounded call-site walk proves the exact direct caller consumes both halves
   before either result storage is overwritten.

Only when both hold may a recovered (not authoritative) call prototype use the
existing double-word INTEGER carrier. Scratch residue alone, a caller-only
live-in, a missing return-path definition, a use after overwrite, an unknown
CFG successor, and a non-returning terminal block all decline the inference.
The cache retains callee-local proof while the final decision remains specific
to each caller.

The proof uses the calling convention's declared result pair, not hard-coded
`rax`/`rdx` names. It therefore applies to every ABI for which the machine model
exposes a two-register INTEGER result and declines Win64, which has no such
contract. Container format does not enter the analysis.

## TDD and validation

Five focused tests cover the positive join, the three principal negative
cases (unconsumed scratch residue, a missing high-half definition on one return
path, and a high half overwritten before use), and the complete modeled-ABI
table. The latter proves the analysis follows the declared pairs for i386
cdecl, ARM32 soft/hard-float, System V AMD64, and AAPCS64, while declining
Win64.

```text
cargo test --features python-ext ir::interprocedural_return::tests -- --nocapture
5 passed; 0 failed

cargo test --features python-ext --lib call_result_split
11 passed; 0 failed

cargo test --features python-ext --lib callee_return_pair
7 passed; 0 failed
```

Fresh release output now declares `choose` as returning `unsigned __int128`,
stores that result once, and obtains the vtable pointer from its upper 64 bits.
A narrow definition-health census reports empty violation lists for
`rust_dyn_apply` at both Rust O0 and O2. The two fixture verdicts remain their
pre-existing `fail` state because full Rust trait-call and optimized tail-jump
recovery are separate unfinished capabilities.

```text
167_rust_trait_objects:rustc:O0:rust_dyn_apply  fail
167_rust_trait_objects:rustc:O2:rust_dyn_apply  fail
SCOPED: 2 lanes of 838 - no regressions in scope
```

## Broad-gate status

The host `@o0 @o2 --full` sweep measured 824 of 838 lanes against the identified
release snapshot. It remained red because `92_anonymous_members:clang:O0`
crashed in the harness and three `138_cpp_operators:clang:O0` functions were
already regressions in the concurrent shared snapshot. Their emitted call
prototypes are ordinary scalar/void types, not the double-word carrier, so none
crossed this new inference path. The sweep also reported three improvements
from other current work. This evidence is not represented as a green full gate.

The existing real `198_aggregate_return_edges` fixture was also exercised at
O0/O2 across i386, ARMv7 Thumb, ARMv7 A32, AArch64, and x86-64. That run is
recorded only as a diagnostic: the installed extension was older than the
concurrently edited Rust tree, and the harness reported 20 baseline
regressions. It therefore does **not** establish cross-architecture integration
coverage for this increment. The clean isolated snapshot proves the ABI-gated
analysis itself; fresh fixture-level evidence still requires a release rebuild
from an otherwise stable tree.

## Remaining work

The inferred carrier preserves the two returned machine words, but does not yet
recover the source-level Rust fat-pointer type. O2 still ends in an unrecovered
indirect tail jump; O0 expresses the virtual call but does not yet recover a
typed trait method. Those are subsequent trait-object and indirect-control-flow
work, not reasons to discard the now-proven call result.
