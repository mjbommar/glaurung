# Machine State — Register File, Memory, Snapshots, Hooks

The `Machine<D: Domain>` holds the executing state. Register file and memory are
both **domain-parameterized** so the same structures serve concrete and symbolic.

## Register file — flat byte-offset guest state

Following VEX/P-code: a flat byte array indexed by `(offset, size)`, so
sub-register aliasing is **structural and automatic** (writing `eax`, `ax`, `al`,
`ah` are all writes at known offsets/sizes into the same backing store).

```rust
pub struct RegFile<D: Domain> {
    /// Canonical full-width register cells, keyed by the arch's register-bank
    /// layout (see arch-abstraction.md). For Concrete, a cell is a u128+width;
    /// for Symbolic, an ExprId. Partial reads/writes use extract/concat.
    cells: Vec<D::Val>,
    layout: &'static RegLayout,   // offsets/sizes/aliases, per-arch DATA
}
```

- `read(reg, width)` → if `width` < cell width, `extract`; the lifter already
  asks for the right width.
- `write(reg, val, width)` → if a sub-register, `concat` into the parent cell.
  The x86-64 "32-bit write zero-extends" rule is *already lowered by the lifter*
  into an explicit `ZExt`, so the register file itself stays dumb.
- Flags are ordinary 1-bit cells (`Flag::Z` etc.) in the same file.
- **Vector/FP banks** (`xmm`/`ymm`/`zmm`, ARM `v0..v31`) are wide cells in the
  same flat model; SIMD helpers read/write them.

`RegLayout` is per-arch static data, not code — adding an arch is a descriptor.

## Memory — softmmu with sparse pages, perms, and COW snapshots

```rust
pub struct Memory<D: Domain> {
    pages: BTreeMap<u64, Page<D>>,    // sparse, keyed by page frame (4 KiB)
    perms: BTreeMap<u64, Perms>,      // R/W/X per page
    dirty: Vec<u64>,                  // page frames written since last snapshot
    baseline: Option<Arc<Snapshot<D>>>,
    code_pages: HashSet<u64>,         // pages we've lifted from (SMC coherence)
}
pub struct Perms { r: bool, w: bool, x: bool }
```

Design points (from QEMU softmmu, bochscpu, wtf/Lucid):

- **Sparse + lazy:** pages exist only when mapped or first touched. An access to an
  unmapped page fires the `MemUnmapped` hook, which may map-on-demand or abort.
- **Concrete bytes fast-path:** a page backed by a `Box<[u8; 4096]>` for the
  Concrete domain; symbolic cells overlay only where a byte is symbolic
  (concretize-with-threshold keeps most of memory concrete — see
  [`symbolic-engine.md`](symbolic-engine.md)).
- **Dirty-page COW snapshots — the forking primitive.** `snapshot()` records the
  baseline; during a run, every store logs its page frame into `dirty`;
  `restore()` copies baseline bytes back **only for dirty pages** → cost ∝ bytes
  modified, *not* address-space size. This is what makes symbolic state forking
  and "what-if" replay cheap (KLEE object-COW / wtf dirty-restore lineage).
- **Permissions enforced:** execute from a non-`x` page, write to a non-`w` page →
  `MemProt` hook → fix or abort (Unicorn semantics).

### Endianness

Read/write honor `MemOp.endian` (added in Phase 0). The engine is endian-agnostic;
the lifter sets endianness per access. Multi-byte assembly uses `concat` in the
order the endianness dictates.

## <a name="hooks"></a>Hooks — Unicorn-compatible taxonomy

```rust
pub enum HookKind { Code, Block, MemRead, MemWrite, MemReadAfter,
                    MemUnmapped, MemProt, Intr, Insn(/* mnemonic */ String) }

pub enum HookAction { Continue, Stop }   // non-Continue aborts (Unicorn semantics)

pub trait Hook<D: Domain> {
    fn on_event(&mut self, m: &mut Machine<D>, ev: &HookEvent) -> HookAction;
}
```

- The hot loop checks `hooks_for(kind).is_empty()` (predictable branch) so a
  zero-hook run pays nothing.
- **`Block` is the default coarse instrumentation point**; `Code` (per-instruction)
  is opt-in because it defeats block-level fast paths.
- Memory hooks fire only for *guest-instruction* accesses, not direct API writes
  (so setup writes don't recurse).
- Across PyO3, hooks are Python callables wrapped as `Hook` impls
  (see [`os-abi-layer.md`](os-abi-layer.md) and the PyO3 phase).

## Lift cache + software block chaining

```rust
pub struct LiftCache {
    blocks: HashMap<u64, Arc<LiftedBlock>>,         // lift once, by start VA
    page_to_blocks: HashMap<u64, Vec<u64>>,         // for SMC invalidation
}
pub struct LiftedBlock {
    ops: Vec<LlirInstr>,                             // immutable, shared via Arc
    succ_cache: Cell<Option<*const LiftedBlock>>,    // resolved constant-target successor
}
```

On a store-hook to a `code_pages` page, evict the page's blocks and any
successor pointers targeting them (per-page bulk eviction; SMC is rare).

## Snapshots vs context

- **Register context** (`snapshot_regs`) is small and fixed-size — cheap clone
  (Unicorn `uc_context_*`).
- **Full snapshot** = register context + memory baseline + dirty log.
- Symbolic forking uses persistent/COW structures so a fork shares everything
  until first write.

## Budgets (bounded execution)

`budget.rs`: per-run instruction budget (decrement per insn/block) →
`Halt::BudgetExhausted`; optional loop detection (visited `(pc, ctx-hash)`);
optional region fence (stop on leaving the target module — the CR3-change analog).
All deterministic; no wall-clock. Mirrors `src/analysis/cfg.rs::Budgets`.

## References
- [`../01-research/emulator-engineering.md`](../01-research/emulator-engineering.md)
- [`determinism.md`](determinism.md), [`arch-abstraction.md`](arch-abstraction.md)
