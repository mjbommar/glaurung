# WP3 renderer-owned local inventory

Commit `7d0095af` removes production definition verification's generic display-
name classifier. The renderer now exports the identity-aware set of C locals
it owns, excluding proven parameters and raw machine-register placeholders;
the structured walk, goto-aware CFG walk, whole-function inventories, and
poison tracking consume that same set. The no-sidecar compatibility verifier
retains its historical `ret` / `local_` / `stack_` / `varN` behavior.

Two adversarial tests prove the boundary: an opaque `scratch_value` that the
renderer declares is checked even without a conventional prefix, while plain
`rbp` machine state is not falsely claimed as a locally produced value. Both
exact tests and all 45 `ir::verify_defs::tests` pass with 4,564 unrelated Rust
tests filtered out.

After a fresh debug extension build, the exact x86-64 O0 declaration/use
invariant and the exact shadow-structurer verification-metadata test pass. The
census records 5,146 declared Rust tests and zero outside every gate; all six
census checks pass after the source commit. The Hello World canary was not
repeated because this increment changes verification metadata rather than
rendered output; its immediately preceding four-cell run remains green. No
broad Rust suite, Python suite, fixture matrix, DecBench, or Joern lane ran.
