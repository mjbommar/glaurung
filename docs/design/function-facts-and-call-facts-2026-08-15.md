# `FunctionFacts` and `CallFactStore`: identity, ownership, and the first step

Status: design note. Nothing here is implemented.
Written 2026-08-15 during the roadmap audit at `dcc62aa`.

This box appears three times in `docs/design/decompiler-roadmap.md` — EPIC 1
(`Add FunctionFacts and CallFactStore keyed by stable function/call IDs`), Phase 4
(`Implement stable FunctionFacts/CallFactStore and SCC propagation`), and by
reference in Phase 5 (`call facts`). It is the most duplicated open item in the
plan, and it has never had a design. That is most of why it has not moved: it
reads as "build an interprocedural analysis framework", which nobody starts on a
Tuesday.

The audit found it is smaller than that, for one reason recorded in §4.

## 1. What exists today

| Thing | Where | Shape |
|---|---|---|
| Per-function prototype facts | `src/program/environment.rs:42` | `HashMap<u64, FunctionPrototypeFact>` keyed by normalized entry VA |
| Caller-side arity facts | `src/program/caller_environment.rs` | recomputed per query, never stored |
| Direct-callee layouts/prototypes | `src/python_bindings/ir/callee_contracts.rs` | `DirectCalleeFacts`, per decompile, thrown away |
| Table-entry layouts | same, `table_entry_layouts` | per decompile, one consumer |
| Call graph | `src/core/call_graph.rs:109` | `nodes: Vec<String>`, edges carry `call_sites: Vec<Address>` |
| Symbol identity | `src/program/symbols.rs:22` | `SymbolId(usize)`, arena index, one linkage spelling = one id |
| Type identity | `src/program/types.rs:13` | `TypeId(usize)`, interned recursive types |

Two things are absent everywhere: a `FunctionId`/`CallSiteId` type, and any
interprocedural fixed point (`grep -rn "scc|tarjan|strongly_connected" src/`
returns nothing).

`ProgramEnvironment` is the de facto function-fact store and it differs from the
canonical stores in a way that matters: on conflicting evidence it *deletes* the
fact and blacklists the address (`environment.rs:872`), where `SymbolStore` and
`TypeStore` retain alternatives with provenance. A `FunctionFacts` that copies
`ProgramEnvironment` would inherit a lossiness the rest of the program
environment has already rejected.

## 2. The stable-ID scheme

Do not invent one. The canonicalizer already exists and is already used by three
independent keys.

```rust
// src/program/image.rs:518
fn normalize_function_entry(format: Format, arch: Arch, va: u64) -> u64 {
    if format == Format::ELF && arch == Arch::ARM { va & !1 } else { va }
}
```

It strips the Thumb bit, which is the only place a function's address has two
spellings. `DiscoveryKey::new`, `EnvironmentKey::new` and
`recover_program_environment` all normalize through it today.

**`FunctionId` = the normalized entry VA of the function's primary chunk.**

```rust
/// A function's identity for the life of one loaded image.
///
/// This is the normalized ENTRY, not a range: `core::Function` carries
/// `chunks: Vec<AddressRange>` because `.cold` splits and MSVC funclets make a
/// function several intervals. Keying on a range would give one function two
/// ids the moment the linker moved half of it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FunctionId(u64);
```

Wrap it in a newtype rather than passing `u64`. The raw-`u64` keying in
`ProgramEnvironment` is why nothing type-checks the difference between an entry
VA, a call-site VA, and a data address today.

**`CallSiteId` = `(FunctionId, u64)`** — the containing function plus the VA of
the call instruction.

```rust
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CallSiteId { pub caller: FunctionId, pub instruction_va: u64 }
```

The instruction VA alone would nearly work, but "nearly" is how a shared tail
of an ICF-merged pair becomes one call site with two callers. Carrying the
caller makes that representable instead of silently wrong. LLIR already
identifies call sites only by instruction VA (`Op::Call` at `LlirInstr.va`), so
the pair is available at every producer with no new plumbing.

Neither id is stable across a re-link, and neither should pretend to be. Anything
that must survive a rebuild belongs to `SymbolStore`, which is keyed on linkage
spelling for exactly this reason. `FunctionFacts` should carry an
`Option<SymbolId>` so a fact can be *attributed* to a durable name without
*being keyed* on one — a static function has facts and no linkage name.

## 3. Where the store lives

`src/program/` beside `symbols` and `types`, owned by `ProgramSession`.

`ProgramSession` already demonstrates two ownership patterns:

* `OnceLock<Arc<T>>` — `symbol_store()`, `type_artifacts()`. Parameterless,
  derived from the image alone, built once.
* `Mutex<HashMap<Key, Arc<T>>>` — `environment()`, keyed by `EnvironmentKey`
  (budgets, calling convention, callback APIs, requested VAs), LRU-capped at 256.

Call facts need discovery and lifting, so they depend on budgets and CC. **Use
the keyed-cache pattern, not the `OnceLock` one.** A `CallFactStore` behind a
`OnceLock` would be built once under whatever budget the first caller happened to
pass, and then be silently wrong for every later caller with a larger one.

Follow `SymbolStore`'s evidence model, not `ProgramEnvironment`'s:

* `FunctionFactEvidence { authority, source, module, version }` mirroring
  `SymbolEvidence`, with `selected()` / `alternatives()` / `conflicts()`.
* A `revision()` counter, as both canonical stores already have, so a consumer
  can cache against it.
* Conflicts retained. The whole argument for interprocedural facts is that two
  callers can disagree; deleting on disagreement throws away the input.

## 4. The first step, and why it is small

`analyze_functions_image_with_seeds` returns `(Vec<Function>, CallGraph)`
(`src/analysis/cfg.rs:4346`). One line of `ProgramSession::discovery` reads:

```rust
// src/program/session.rs:263
let (functions, _call_graph) = analyze_functions_image_with_seeds(&self.image, budgets, &key.seeds);
```

**The SCC input is computed on every analysis and discarded one line after it is
produced.** The first commit on this box is not an analysis framework; it is
keeping that value, re-keying its string nodes to `FunctionId`, and adding a
condensation. Everything else — the facts, the monotone join, the propagation
order — is downstream of having a call graph the session owns.

Two properties to pin at that first step, because they are cheap now and
expensive later:

1. The condensation is deterministic. Node order must come from sorted
   `FunctionId`, not from `HashMap` iteration, or every downstream fact becomes
   run-dependent. Diary entry 20 ("Determinism and parallel equivalence")
   already paid for this lesson once in the fixture harness.
2. An unresolved indirect call is an EDGE TO UNKNOWN, not a missing edge. A
   function whose only outgoing call is indirect must not condense as a leaf with
   complete facts — that is the same fail-open shape as `call @0x0`.

## 5. What NOT to do

* Do not key facts on function NAME. `core::Function.name` is `sub_<VA>` on
  stripped binaries and is rewritten by naming passes mid-pipeline.
* Do not put the store behind the decompile-time `DirectCalleeFacts`. That
  structure is per-decompile by design, and its author deliberately kept
  `table_entry_layouts` unreachable from other consumers; promoting it would
  reintroduce exactly the coupling that isolation was buying.
* Do not build propagation before the clobber contract (Phase 3). An
  interprocedural fixed point over call effects whose every call is `Opaque`
  converges immediately to "unknown everywhere", which is sound, useless, and
  looks like progress.
* Do not assume "implemented" means "connected". `SymbolStore` shipped in
  `6783274` on 2026-08-14 and had zero production consumers until `4af32f1` the
  next day; every caller in between lived in `session_tests.rs`.
  A `CallFactStore` with no migrated consumer is the same artifact.
