# WP9 target-aware register-read identity

Date: 2026-09-03

## Scope

This increment fixes one machine-model fact class without claiming WP9 is
complete: a sub-register read observes the current value of its architectural
parent, while a bit-preserving sub-register write does not independently define
that whole parent.

The production pipeline now computes target-aware SSA. SSA accepts separate
definition and use canonicalizers, value numbering consumes the exact
`SsaValue { base, version }` for each use, and MIR inventories those exact SSA
storage identities rather than re-canonicalising every operand as a write.
The distinction is format-independent after `ProgramImage` has produced a
`TargetSpec`; ELF, PE, and Mach-O do not select separate SSA implementations.

Implemented register-view behavior:

- x86-64 reads of `ax`, `al`, and `ah` use the reaching `rax` SSA version;
- AArch64 reads continue to share `wN`/`xN` identity through the existing view
  descriptor;
- ARM32 retains its explicit alias canonicalisation; and
- x86-32 deliberately retains the legacy architecture-blind identity until
  its lifter, ABI consumers, and register views can migrate together.

The last item is a compatibility boundary, not a claim that IA-32 partial
register semantics are complete.

## RED and focused GREEN evidence

The original x86-64 RED test defined `rax`, read `ax`, and observed the read as
the unrelated live-in `ax#0`. It now resolves to the exact reaching `rax`
definition. A second regression test proves value numbering emits the parent
identity while retaining the operation's 16-bit source width.

```text
cargo test --features python-ext --lib ir::ssa::tests
11 passed; 0 failed

cargo test --features python-ext --lib ir::value_number::tests
43 passed; 0 failed

cargo test --features python-ext --test register_view_semantics
24 passed; 0 failed
```

The first full gate exposed a MIR storage-inventory panic in
`arm_aliases_are_canonical_only_under_the_arm_target`: the x86 half read `sp`,
SSA correctly identified the use as `rsp`, but MIR had inventoried only the raw
write-canonicalised spelling. Switching MIR storage discovery and unreachable
use handling to the exact SSA bases fixed the interaction. The focused MIR test
then passed.

An isolated-target run avoided concurrent Cargo artifact collisions and passed
all Rust, integration, and doctest targets at that source snapshot:

```text
cargo test --target-dir /tmp/glaurung-wp9-target --features python-ext
3109 library tests passed; 3 ignored
all ordinary integration targets passed
1 doctest passed; 1 ignored
```

The symbolic feature also compiled after the shared identity changes:

```text
cargo test --features symbolic --no-run
exit 0
```

Before commit, the seven owned paths/hunks were applied to a detached worktree
at `d2c0ba95`, excluding every concurrent unstaged change. In that exact staged
tree, all 11 SSA tests, the new value-numbering regression, and the MIR storage
regression passed. Running the entire value-numbering module there produced 40
passes and one fixture-load failure because the temporary worktree intentionally
used unsmudged Git LFS pointer files (`Unknown file magic`), not because an
assertion failed. The corresponding 43-test module had already passed in the
primary worktree with materialized fixtures.

## Real output improvement

The verifier originally exposed `cpp_template_int16:gcc:O2` returning an
undefined/self-referential value after a 16-bit accumulator read. On the release
build, the final output instead assigns the defined accumulator (`ret = total`)
and emits no `GLAURUNG_VERIFY_DEFS` warning.

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp uv run python tools/dectest.py \
  137_cpp_templates:gcc:O2:cpp_template_int16 \
  75_order_book:gcc:O2:match_order --full --show

137_cpp_templates:gcc:O2:cpp_template_int16  pass
75_order_book:gcc:O2:match_order             pass
SCOPED: 2 lanes of 838 - no regressions in scope, 1 improvement
```

The measured extension SHA-256 was
`c482afbd8af4c2cf4f80f24d8df9c89ef4efc5c8cc6a527da3a3b79734491689`.
Concurrent edits to `src/ir/naming.rs` occurred after that build, so a later
freshness check correctly marked the extension stale; the hash identifies the
artifact used for the output above rather than claiming it represents the
subsequent shared worktree.

## Rejected IA-32 experiment

An explicit 32-bit x86 register-view descriptor was prototyped and passed unit
tests for `eax`/`ax`/`ah`, SSA, execution, and symbolic compilation. The required
architecture sweep rejected it:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp uv run python tools/dectest.py \
  @o0 @o2 --arch i386 --full
SCOPED: 410 lanes of 3304 - 241 REGRESSIONS
```

The descriptor and execution changes were removed. The regressions persisted
until target-aware SSA explicitly preserved the historical IA-32
canonicalisation, demonstrating that the i386 lifter and downstream ABI/naming
logic currently depend on that spelling. With the compatibility branch the same
sweep fell to 3 regressions and 20 improvements. Those remaining changes are in
a heavily concurrent dirty worktree and include aggregate-call and 64-bit-pair
rendering families; they are not accepted or attributed to this increment, and
no architecture baseline was refreshed.

This is useful negative evidence for WP9: IA-32 register views must migrate with
their lifter and consumers as one measured unit. Introducing an apparently
correct table in isolation is not safe.

## Current gate state and remaining work

After additional concurrent AST/prototype edits, a later isolated full gate
failed five `ir::ast::tests` assertions concerning prototype spelling. The
target-aware SSA, value-number, register-view, and MIR-focused tests remained
green. This report therefore records the full gate as green only at the earlier
identified snapshot and the current shared-worktree gate as red; it does not
hide unrelated failures.

Still required for WP9:

- inventory and migrate IA-32 lifter/ABI/register consumers together;
- add the planned ARM32 core/VFP overlap model;
- sweep AArch64 and ARM32 architecture baselines for their eventual fact-class
  migrations;
- add the mnemonic capability census and reviewed exemption file; and
- ratchet silent register writers and `Op::Unknown` totals.
