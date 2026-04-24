# Decompiler pipeline

Glaurung's pseudocode output is produced by a straight-line sequence of
~20 small passes over a shared AST. Each pass has a single, narrow
responsibility; together they turn raw decoded instructions into a
C-like listing with named calls, string literals, stack locals, and
recognised prologue / epilogue / canary idioms.

This document enumerates every pass in execution order. Entry point:
`src/python_bindings/ir.rs::decompile_at_py` (mirror in `decompile_all_py`).
Individual passes live under `src/ir/`.

The pipeline is the same for x86-64 and AArch64; architecture-specific
passes gate themselves on the calling-convention hint carried through the
Python binding.

## Stage 1 — Lift

| # | Pass | Source | Purpose |
|---|------|--------|---------|
| 1 | `analyze_functions_bytes` | `src/analysis/cfg.rs` | CFG discovery: BFS over basic-block starts, bounded by budget. Produces a `Vec<Function>` with per-block VA ranges. |
| 2 | `lift_function_from_bytes` | `src/ir/lift_function.rs` | Dispatches each function's raw bytes through the arch-specific lifter (`lift_x86` / `lift_arm64`) to produce an `LlirFunction`. |

## Stage 2 — Structural recovery

| # | Pass | Source | Purpose |
|---|------|--------|---------|
| 3 | `compute_ssa` | `src/ir/ssa.rs` | Dominator-frontier phi placement + Cytron renaming on register VRegs. |
| 4 | `recover` | `src/ir/structure.rs` | Turn the CFG into a `Region` tree: `Seq / IfThen / IfThenElse / While / Unstructured`. Reducible shapes collapse; everything else falls back to labelled gotos. |

## Stage 3 — Lowering

| # | Pass | Source | Purpose |
|---|------|--------|---------|
| 5 | `lower` | `src/ir/ast.rs` | Walk the Region tree, producing the initial `Function { body: Vec<Stmt> }`. One-to-one: each LLIR op becomes one Stmt. |
| 6 | `fold_returns` | inside `lower` | Recognise `%ret = expr; Return;` → `Return { value: Some(expr) }`. |
| 7 | `extract_cond_and_strip` | inside `lower` | Hoist the flag-producing `Cmp` out of an If's cond block into the If's cond expression (`if (%zf)` → `if ((%rax == 0))`). |

## Stage 4 — Expression-level simplification

| # | Pass | Source | Purpose |
|---|------|--------|---------|
| 8 | `reconstruct` | `src/ir/expr_reconstruct.rs` | Inline single-use `%t0` temporaries into their consumers. Converts the lifter's flat three-address form into nested expressions. |
| 9 | `fold_constants` | `src/ir/const_fold.rs` | Collapse identities: `(X ^ X)` → `0`, `(X + 0)` → `X`, `(2 * 3)` → `6`, etc. Bottom-up. |
| 10 | `prune_dead_flags` | `src/ir/dce.rs` | Drop `%cf / %slt / %sle / %sf` flag writes whose destination flag is never read anywhere in the body. |

## Stage 5 — Semantic uplift

| # | Pass | Source | Purpose |
|---|------|--------|---------|
| 11 | `reconstruct_args` | `src/ir/call_args.rs` | Fold `%arg0 = X; call foo()` into `call foo(X);` per calling convention (SysV AMD64, AArch64). |
| 12 | `resolve_names` | `src/ir/name_resolve.rs` | Rewrite `Expr::Addr(va)` as `Expr::Named { name }` using the binary's symbol table + PLT/IAT/Mach-O-stubs maps. |
| 13 | `fold_string_literals` | `src/ir/strings_fold.rs` | Replace `Expr::Addr(va)` / `Expr::Named` pointing into `.rodata` with `Expr::StringLit("…")` when the bytes are printable C strings. |
| 14 | `recognise_canary` | `src/ir/canary.rs` | Rewrite `*(u64)fs:[0x28]` → `Expr::Named { name: "__stack_chk_guard" }`. Knows `fs:[0x0]` / `fs:[0x30]` too. |

## Stage 6 — Naming and promotion

| # | Pass | Source | Purpose |
|---|------|--------|---------|
| 15 | `promote_stack_locals` | `src/ir/stack_locals.rs` | Rewrite `*(uN)&[%rsp+K]` references as `%stack_N` / `%stack_top` / `%local_N` based on stack register + offset. |
| 16 | `apply_role_names` | `src/ir/naming.rs` | `%rdi → %arg0`, `%rax → %ret`, other GPRs → `%varN` (first-appearance order). Stack registers preserve their name. Preserves any `stack_*` / `local_*` aliases set by #15. |
| 17 | `collapse_canary_save` | `src/ir/canary.rs` | Prologue: `%ret = __stack_chk_guard; store %stack_0 = %ret;` → `// stack canary: save guard to %stack_0`. Exit: `%X = %stack_0; %X = (%X - __stack_chk_guard); if (%zf) goto L;` → `// stack-canary check`. |

## Stage 7 — Architecture-specific prologue / epilogue recognition

| # | Pass | Source | When | Purpose |
|---|------|--------|------|---------|
| 18a | `recognise_arm64_prologue` | `src/ir/arm64_prologue.rs` | `cc == Aarch64` | Collapse the `stp fp,lr` + `sp -= N` + `fp=sp` prologue into a single `// aarch64 prologue:` comment. Mirror epilogue: `%fp=%stack_N; %lr=%stack_M; sp+=N; return;` → `// aarch64 epilogue:` + `return;`. |
| 18b | `recognise_x86_prologue` | `src/ir/x86_prologue.rs` | `cc == SysVAmd64` | Collapse `push rbp; mov rbp,rsp; sub rsp,N` into `// x86-64 prologue:`. Mirror `rsp=rbp; pop rbp; return;` (from `leave`) → `// x86-64 epilogue:`. Also handles the `-fomit-frame-pointer` form: `rsp+=N; return;` → `// tear down frame`. |

## Stage 8 — Dead-code and idiom elimination

| # | Pass | Source | Purpose |
|---|------|--------|---------|
| 19 | `eliminate_dead_stores` | `src/ir/dead_stores.rs` | Intra-body live-variable pass. Drops `%X = E;` when X is overwritten before any read, drops `%X = %X;` self-assigns, and drops ABI-bookkeeping zeroes to `%fp`/`%lr` in `_start`. |
| 20 | `rematerialise_stack_ops` | `src/ir/stack_idiom.rs` | `%rsp -= 8; store %stack_top = X;` → `push X;`. Mirror for pop. Also drops a trailing `%rsp += N;` immediately before `Return`. |
| 21 | `prune_unreferenced_labels` | `src/ir/label_prune.rs` | Drop `L_xxx:` labels that no `Stmt::Goto` targets. |

## Stage 9 — Render

One of the three renderers:

| Renderer | Source | Output style |
|----------|--------|--------------|
| `render` | `src/ir/ast.rs::render` | Default plain text. No type annotations. |
| `render_with_types` | `src/ir/ast.rs::render_with_types` | Adds `(u64*) / (bool) / (fnptr)` annotations from the type-recovery pass. |
| `render_c` | `src/ir/ast.rs::render_c` | C-like: no `%` prefix, no type annotations, `fn <name> { ... }` header. |

The type-recovery pass (`src/ir/types_recover.rs::recover_types`) runs on
the pre-renamed LLIR and produces a `TypeMap` that the
`render_with_types` renderer consumes; a small remap step in the Python
binding translates the physical-register keys back into the role-names
the AST carries post-#16.

## Op-level coverage

Lifter mnemonic coverage is deliberately narrow but grows as needed:

* **x86 / x86-64** (`src/ir/lift_x86.rs`): `mov`, `lea` (RIP-relative and
  base+index+scale+disp), `add`/`sub`/`mul`/`and`/`or`/`xor`/`shl`/`shr`/
  `sar`/`imul`, `inc`/`dec`, `not`/`neg`, `cmp` (reg/mem), `test`,
  `push` (reg/imm/mem), `pop`, `call` near direct / indirect,
  `ret`/`retf`, `jmp` / `jcc`, `nop` / `endbr32` / `endbr64`,
  `movaps`/`movups`/`movdqa`/`movdqu` as sized loads/stores, `leave`.
  Anything else is `Op::Unknown { mnemonic }`.
* **AArch64** (`src/ir/lift_arm64.rs`): `mov`, `movz`, `adrp`,
  `add`/`sub`/`and`/`orr`/`eor`/`lsl`/`lsr`/`asr`/`mul`, `cmp`,
  `ldr` / `str` (all width variants, including PC-relative literal and
  post-indexed writeback), `ldp` / `stp` (including pre- and post-
  indexed writeback — see `capstone.rs` for how writeback is surfaced
  as a trailing Immediate operand), `cbz` / `cbnz`, `b` / `bl` / `br` /
  `blr`, `b.<cond>`, `ret`, `nop`.

## Testing

Every pass has its own unit-test module in the same source file. The
pipeline as a whole is exercised by:

* `python/tests/test_ir.py` — end-to-end Python binding tests.
* `python/tests/test_cli_decompile.py` — CLI regressions that assert
  both output styles and the prologue / epilogue comments appear.
* Real-binary smoke tests inside each pass's test module, guarded by
  `#[cfg(test)] if !path.exists() { return; }` so they skip gracefully
  when the binary isn't committed to the repo.
