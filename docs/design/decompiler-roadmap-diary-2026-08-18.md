# Decompiler roadmap — execution diary, 2026-08-18

Continues [the 2026-08-16 diary](decompiler-roadmap-diary-2026-08-16.md).
Entry numbering is continuous across files; the roadmap cites entries by number.

## Entry 70 — 8.6% of the tree is never compiled by the command we call the gate

`CLAUDE.md` has warned for days that plain `cargo test` skips
`src/python_bindings/` and that a green result over code it never built is the
worst kind. The same trap is an order of magnitude larger one directory over,
and nobody had looked.

`src/lib.rs:65` is `#[cfg(feature = "symbolic")]`, and `symbolic` is in neither
`default = ["triage-core"]` nor
`python-ext = ["pyo3", "pyo3/extension-module", "exec"]`.

I proved it rather than reading the manifest, because reading the manifest is
what everyone had already done. Appending `this is not valid rust @@@` to
`src/symbolic/expr.rs`:

```
cargo build --features python-ext   ->  0 errors
cargo build --features symbolic     ->  2 errors
```

**21 files, 14,649 product LOC — 8.6% of a 170,474-line tree — that
`cargo test --features python-ext` does not compile.**

### What was hiding in there

- **All three SMT solver backends had not compiled for seventeen days.**
  `b03d5057` (2026-07-31) added `BinOp::LogicalAnd` and `BinOp::LogicalOr`,
  updated `symbolic/expr.rs`, and updated no backend. `axeyum_backend`,
  `z3_backend` and `bitwuzla_backend` all carried the same ten-arm match.
- **`triage-parsers-extra` had been broken for 350 days.**
- **A fourth copy of the same E0004** in `examples/axeyum_bench_primitives.rs`,
  which none of us knew about and which only `--all-targets` finds.
- **`symbolic/explore.rs` set `product_max_loc` for this entire refactor
  program** — the measure the program is judged by — while being invisible to
  every command in CLAUDE.md's build/test block.

### I was wrong about why nobody noticed, and the truth is worse

I reported that no script runs the solver features. In fact
`scripts/lint-rust.sh:14` runs `cargo clippy --all-targets --all-features --
-D warnings`, which would have caught **every one** of these. Two things
defeated it:

1. `--all-features` turns on `solver-bitwuzla`, whose `build.rs` **panicked**
   when Bitwuzla was absent — so the script died inside the build script before
   clippy saw a line, on every machine without Bitwuzla, which is every machine.
2. **Nothing calls it.** Nor `scripts/harden.sh`. And no GitHub workflow runs
   cargo at all — CI builds wheels through maturin. The only Rust gate in the
   repository was `decbench-local-gate.sh` lane 1: one configuration,
   `--lib --tests`, which is also why the broken examples were invisible.

So the repository had a lint that would have caught this, and three independent
reasons it never ran. That is a more uncomfortable finding than "there was no
lint", and it generalises: **a gate that is not called is worse than a missing
gate, because its existence is mistaken for coverage.**

### The fix, and mutation-testing the gate itself

`scripts/feature-build-gate.sh` — 11 `cargo check --all-targets` lanes, 4m31s
warm, exit 1 on any failure, wired into `decbench-local-gate.sh` as lane 1a and
into a new GitHub workflow.

A gate is a claim, so it gets tested like one. Reverting the `translate.rs` fix
makes lanes 5, 6, 10 and 11 fail and the script exit **1**; restoring it exits
**0**. `build.rs` gains `GLAURUNG_BITWUZLA_TYPECHECK_ONLY=1` so `cargo check`
can type-check the bitwuzla backend without the library present — which also
revives the two lint scripts.

The feature coverage table, previously unenumerated anywhere:

| feature | `#[cfg]` sites | gated before | now |
|---|---:|---|---|
| `python-ext` | 277 | decbench lane 1, CI wheels | lane 2 |
| `solver-axeyum` | 62 | **none** | lane 5 — broken 17d |
| `solver-z3` | 56 | **none** | lane 9 — broken 17d |
| `solver-bitwuzla` | 31 | **none**, unbuildable | lane 7, type-check only |
| `triage-parsers-extra` | 4 | **none** | lane 8 — broken 350d |
| `symbolic` | 2 | **none** | lane 4 |
| `dev-oracle` | 1 | **none** | lane 11 |
| `triage-core`/`-heuristics`/`-containers` | **0** | n/a | vestigial — gate no code at all |

### The semantics question, which was the real work

`unreachable!()` was the tempting arm and would have been a panic. Two `Expr`
types share one `BinOp`: the decompiler AST (where `ir/guard_chain.rs`
synthesises `&&`/`||`, never reaching a solver) and the symbolic pool. The
variants reach the second through **deserialization** —
`symbolic/native_trace.rs:469` parses `"logical_and"` from a JSON pack, and
`ordered_replay.rs:314` imports that pack into the pool a backend then
translates. A `LogicalAnd` in a file on disk was a panic in a solver call.

And `ordered_replay.rs:316-320` settles what the arms must *do*: it re-renders
every imported pack through the text bridge and rejects it unless the rendering
hashes to the recorded constraint. The native backends do not merely aspire to
agree with `expr.rs` — replay breaks if they don't. All three now implement its
truthiness renderer exactly: coerce to the node width, **then** test `!= 0`,
then `ite`. Coercion order is load-bearing, because truncation can zero a
non-zero operand.

## Entry 71 — the bug under the bug: sixteen-bit division was being discarded

Fixture `194_narrow_return_widths` found that byte `mul`/`div` were never
lifted — `accumulator_halves` matched 64/32/16 and returned `None` below, so the
instruction fell to `Op::Unknown` and gcc's reciprocal constant `0xAB` appeared
nowhere in the output.

Fixing that surfaced something bigger. **Even at sixteen bits the lowering
*wrote* `VReg::phys("ax")` and `phys("dx")`** — bare partial-view names.
`regview::ssa_parent` declines to merge a bit-preserving view with its parent,
and every *read* of such a view is lowered by `read_view_ops` as an extract from
`rax`/`rdx`. Definition and use were two unrelated SSA names, so the result was
silently discarded. `185:gcc:O0:divide_unsigned_shorts` shows it plainly —
`divw -0x2(%rbp)` recovered as

```c
return (unsigned int)((unsigned short)(((unsigned int)(dividend) & 0xffff)));
```

with the divide simply gone.

`snapshot_accumulator_half`'s existing doc comment had fixed only the **read**
side of this hazard. The write side had never been done, and nothing pointed at
it because the corpus had no fixture that divided at a sub-word width — which is
exactly what 194 added. **Nine cells were predicted; forty-four moved.**

### The scope argument for `_Bool`, which is the part worth keeping

The second defect was that a narrow return is never truncated to its declared
width. I asked the agent to measure the blast radius and choose between
"truncate whenever wider than declared" and "truncate only `_Bool`", expecting a
size answer.

The right answer is a language answer. **C's return conversion is the assignment
conversion.** For every integer type except `_Bool`, 6.3.1.3 defines it as
reduction modulo 2^N — precisely the machine truncation we would spell, so the
cast is *provably* a no-op, not merely usually one. `_Bool` alone (6.3.1.2)
makes the conversion a **test**, which cannot recover a low byte from a
register-width value. The rule is "narrow where the language's own conversion is
not a truncation", and that set is `{_Bool}`.

It is also the smaller rule — 3 affected definitions against 704 — but that is a
coincidence, not the reason.

I also had the file wrong, and the correction matters:
`fold_typed_return_abi_extensions` **cannot see this case**, because
`inferred_return_width` comes from the recovered `TypeMap` and
`types_recover.rs:100` maps `TypeHint::BoolLike` to `"int"` — width 4, never 1.
`_Bool` exists only in the DWARF `CallPrototype` the renderer prints.

## Entry 72 — a correctness bug I traced correctly and that cannot happen

I traced the jump-table trim by hand and was confident: `attached` is built one
edge per table entry with no dedup; `extras` is the unproven suffix; the retain
removes **by value**, so a target present in both the proven prefix and the
trimmed suffix loses every edge. And `repair.rs:408` dedups `successor_ids`, so
the duplicate edges were harmless before — but dedup cannot restore a successor
that was never added.

Every step of that is true. The overlap still cannot occur, and the measurement
is the entry.

Instrumented over **12,249 binaries** — `samples/`, a seeded sample of system
ELFs, the whole fixture corpus, and 10,272 synthetic variants:

```
4,712 needs_bound_proof dispatches · 38 reached the trim · 0 overlaps
```

Both ingredients are individually common — `/bin/grep` has a table with
`n=153 distinct=53 dup=100` — but never together, and there is a structural
reason, verified byte-for-byte in `.rodata`. `discover_jump_tables` builds the
**longest run** of section words decoding to executable VAs, so the over-read
runs into the *next* table, and entries of table 2 read relative to `base1`
resolve to `T_j − 4·N1`. In one trimming binary: table 1 at `0x2000` with six
arms, table 2 at `0x2018` with real targets `0x12fc…0x13ff`, over-read as
`0x12e4…0x13e7` — exactly `real − 0x18`. **`extras` is always shifted garbage in
a different address range, never a repeat of a proven arm.**

Fixed anyway, in the multiplicity-keyed form, because the fix is free. Provably
a no-op at overlap zero, so no cell moved and no baseline needed regenerating.

Three things this produced that are worth more than the fix:

- **The dedup alternative was refuted concretely.** `resolved_targets` is a
  prefix of the raw scan, so deduping `attached` alone breaks
  `attached.starts_with(targets)` and sends every duplicate-bearing dispatch to
  `invalid_dispatches`, losing *all* its arms. Deduping both sides makes `arms`
  count distinct successors rather than table entries. **Edge multiplicity is
  load-bearing:** `clang_o2_shared_case_bodies` asserts `succs.len() == 8` over
  seven distinct blocks — that is how `case 2: case 5:` survives.
- **`arms` and the edge set can no longer disagree.** The helper returns the
  surviving count and the caller writes `*arms = kept`, so the arm count is read
  *off* the edge set instead of asserted beside it. That they could disagree at
  all was arguably the deeper defect.
- **The route that *would* fire it is now named.** `combine_dispatch_bounds`
  applies a fallthrough-only index bound to a dispatch block unconditionally,
  even when that block has a predecessor that does not satisfy the guard. There
  `extras` would contain *real* table entries, where duplicates are guaranteed.
  No binary was found where it bites, so it is filed rather than changed —
  altering a soundness-critical bound on an unmeasured hypothesis is how the
  next entry in this diary gets written.

And a corpus fact worth acting on separately: the 716 fixture binaries produce
**three** bound-proof dispatches and **zero** trims. The entire trim path has no
fixture coverage, because every observed trim was `gcc -O1` and
`REQUIRED_MATRIX` is `gcc/clang × O0/O2`.
