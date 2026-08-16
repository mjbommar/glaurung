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

---

## 6. Correction, measured 2026-08-15 (after §1–§5 were written)

§4 above says the first step is "keeping that value" — retaining the `CallGraph`
that `session.rs:263` discards. **That is wrong, and the box should not be
implemented that way.** The value being discarded is not fit for the purpose it
was going to be kept for. Four measurements, taken with a throwaway probe built
against `analyze_functions_image_with_seeds`:

**1. It fails its own validator.** On a plain dynamically linked hello-world:

```
cg.validate() = Err("Edge references unknown caller function: _start")
```

The cause is two name generations in one structure. `cg.add_node(f.name)`
(`cfg.rs:5144`) runs inside the discovery loop, *before* the symbol-table, PE
export, DWARF and FLIRT rename passes (`cfg.rs:5149-5257`). The edge loop
(`cfg.rs:5266`) builds `name_by_va` from the *final* names. A function
discovered as `sub_1149` and later renamed `main` is therefore `sub_1149` in
`nodes` and `main` in `edges`. Every method that iterates `self.nodes` —
`root_functions`, `leaf_functions`, `call_depth`, `has_cycles` — is unreliable
for that reason.

**2. Roots are not nodes.** Only the *callee* gets `add_node` in the edge loop
(`cfg.rs:5280`), so a caller reached only through the `sub_{:x}` fallback never
becomes a node. On the same binary, 5 edge callers — `main`, `_start`,
`__do_global_dtors_aux`, `_GLOBAL__sub_I_main`, `_ZL15static_functionv` — are
absent from `nodes`. A condensation over `cg.nodes` would omit exactly the
functions an analyst asks about.

**3. 41% of the node set has no function behind it.** 111 of 270 nodes on that
binary are `sub_<hex>` spellings for PLT stubs and targets outside the
discovered set. The node set is a mix of real functions and synthetic strings.

**4. Names are the key, and the design note already said not to use them (§5).**
Two static functions sharing a spelling collapse to one node; `add_node` dedups
by string.

### What to build instead

`Function::callees: HashSet<Address>` is already populated by discovery
(`cfg.rs:2113`) and already consumed twice — `ir/lift_function.rs:762` and
`ir/name_resolve.rs:332`. It is VA-level, it is per-function, and
`ProgramSession` already caches the `Arc<[Function]>` that carries it. Building
the identity-keyed graph from that costs one O(V+E) pass over an artifact the
session already owns, needs no change to `analysis/cfg.rs`, and produces a node
set that is exactly the discovered functions — roots included.

That is what `src/program/call_graph.rs` now does. The `CallGraph` return value
stays discarded, with a comment at `session.rs` saying why.

### The edge set is a LOWER BOUND, and that changes the contract

`§4` point 2 asked for "an edge to unknown, not a missing edge". **That cannot
be honoured from the data discovery keeps today.** `analysis/cfg.rs:1488` reads

```rust
let resolved_target = immediate_target(&ins)
    .or_else(|| indirect_memory_target(facts.image, data, &ins, bits));
if let Some(tgt) = resolved_target {
    call_edges.push(FunctionXref { ... });
}
```

An *unresolved* indirect call produces no xref at all. The unresolved sites are
recorded — `stats.unresolved_indirect` — but on `FunctionDiscoveryStats`, which
`analyze_functions_image_with_seeds` also drops. So a function whose only
outgoing call is an unresolved indirect one is indistinguishable from a leaf.

`ProgramCallGraph` therefore documents its edges as a lower bound and refuses to
offer `is_leaf()`. `shares_component() == true` is proof of a cycle;
`false` is not proof of acyclicity. Consumers may use it to justify spending
*more* effort and never as a termination guarantee. Making unresolved indirect
calls representable requires surfacing `stats.unresolved_indirect` alongside the
functions, which is a separate change to `analysis/cfg.rs` and is not done.

### `CallSiteId` is not implementable from what the session caches

§2 proposes `CallSiteId = (FunctionId, instruction_va)`. The identity is right,
but there is no producer for it on this path: `Function::callees` is a
`HashSet<Address>` of *targets* and records no call-site VAs. The site VAs exist
only in `calls_all` inside `analyze_functions_bytes_within`, which converts them
to `CallGraphEdge::call_sites` and drops the VA-level form.

So `CallFactStore` — which is keyed by call site — is strictly larger than
`FunctionFacts`, and requires an `analysis/cfg.rs` change first.
`src/program/call_graph.rs` ships `FunctionId` and deliberately does **not**
ship `CallSiteId`, rather than shipping an identity nothing can construct.

### What the truncation actually costs, and what a cycle actually costs

Census over all 762 built objects in `tests/decompiler_fixtures/build/`, using
the VA-level graph:

| | images | share |
|---|---|---|
| call chain reaches depth >= 3 | 222 | 29% |
| contains a mutual-recursion SCC | 8 | 1% |

with 34 mutual SCCs and 46 self-recursive functions in total; the 8 cyclic
images are `112_recursion_shapes` (gcc/clang -O0) and six `rustc` fixtures.

That asymmetry is the finding. `recover_direct_callee_definition` truncates at
one nested layer, and its doc gives mutual recursion as the reason — a shape
present in 1% of the corpus. It pays for that guard on the 29% whose call chains
run deeper than the truncation can follow. The guard and the depth limit were
conflated into one boolean; they are separate concerns, and the SCC condensation
is what lets them be separated. `include_grandcallees: bool` is now
`NESTED_CALLEE_DEPTH` (the sole termination guarantee) plus a separate SCC
guard.

**And the depth increase the census suggests does not pay.** Raising
`NESTED_CALLEE_DEPTH` to 2 was measured: 1457 decompiled functions over 300
fixture objects came out byte-identical, and `dectest @o0` + `@o2` (728 lanes)
showed no verdict change. The 29% is not the size of a prize. The callee
analysis is demand-driven on the rendered function's direct callees, so a long
chain somewhere in the image does not imply a third layer changes that
function's argument layouts. Reverted to 1.

Which leaves an honest gap to name: at depth 1 the SCC guard cannot alter an
outcome, because `remaining_depth - 1` is 0 either way. `ProgramCallGraph` is
built and consulted on every decompile — at 1.2% of discovery cost, on an
artifact already cached — but nothing yet depends on its answer.

### Which fact `FunctionFacts` should carry — and why it is not built yet

Of the three candidates, only one has a consumer today:

| fact | computed | consumers | monotone |
|---|---|---|---|
| does it return | `analysis/call_semantics.rs:18`, a 21-name list resolved to PLT/IAT VAs, cached in a `OnceLock` on `ProgramImage` | 4, incl. **CFG discovery itself** (`cfg.rs:1499`) | trivially — it is a constant |
| does it clobber memory | **nowhere**; `memory_ssa.rs:556` makes every call an unconditional `Clobber` | none | would be, from `true` down |
| prototype / arity | 3 separate producers | `prepare_llir_for_lowering` x4 | **no** — `environment.rs:872` deletes the fact and blacklists the address on conflict |

Noreturn is the only fact with real consumers, and today it is a *name list*,
not an inferred property. `FunctionFlags::NO_RETURN` exists (`core/function.rs:49`)
and is never set by anything. The interesting version — "this function never
returns because every path ends in a noreturn call" — is exactly an SCC
propagation, and it is monotone in the safe direction: start at may-return,
move to never-returns only on proof, never retract.

**But it cannot be propagated back to its main consumer.** CFG discovery reads
noreturn to decide where functions *end* (`cfg.rs:1499`), and a body-derived
noreturn needs the bodies discovery has not produced yet. That is a genuine
cycle between function boundaries and function facts, and `call_semantics.rs:3-8`
already flags it. The three downstream consumers (`return_type.rs:130`,
`ast.rs:8054`, `callee_contracts.rs:650`) could take a propagated fact without
that circularity — but that is a real design decision, not a free one.

Meanwhile the design note's own §5 says not to propagate before the clobber
contract lands, and the clobber contract does not exist at all.

**Conclusion: do not build `FunctionFacts` yet.** The graph and the condensation
are the reusable part and they are now landed with a consumer. The store should
wait for either the clobber contract (Phase 3) or an explicit decision about the
discovery/noreturn cycle. Building it now would repeat the `SymbolStore` shape
this note warns about in §5 — implemented, unconnected, and counted as done.
