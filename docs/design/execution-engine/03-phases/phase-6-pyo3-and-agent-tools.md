# Phase 6 — PyO3 Surface & LLM Agent Tools

**Goal:** surface the engine to Python and to the LLM agent layer, with
deterministic output, cost guards, and KB writeback. Specs:
[`README.md`](../README.md) (data flow), `python/glaurung/llm/`, `python/glaurung/kb/`.

**Feature gate:** `python-ext` (existing) for the bindings; engine features as
needed.

## Tasks

- **6.1 `src/python_bindings/exec.rs`** — PyO3 surface mirroring existing
  `python_bindings/ir.rs` (dict-based for forward-compat). Expose:
  - `emulate_function(binary, va, *, args, hooks, budget, os) -> dict`
    (final regs, memory writes, resolved indirect targets, stdout/log).
  - `Emulator` class: `map`, `write_mem`/`read_mem`, `set_reg`/`get_reg`,
    `add_hook(kind, callable)`, `run`, `snapshot`/`restore`.
  - `concolic`/`explore` entry points (feature `symbolic`): `find_inputs(binary,
    va, symbolize, targets, budget) -> list[Witness]`.
  *Test:* `uvx pytest` round-trips; determinism (call twice, equal results).
- **6.2 Hook callbacks across the GIL.** Wrap Python callables as `Hook` impls;
  acquire the GIL only when a hook is registered; document the perf cost. *Test:* a
  Python `MemWrite` hook observes the right addresses.
- **6.3 CLI commands** (`python/glaurung/cli/commands/`): `glaurung emulate
  <bin> <va>` and `glaurung find-inputs <bin> <va> --reach <addr>`. *Test:* CLI
  smoke tests on `samples/`.
- **6.4 Agent tools (`python/glaurung/llm/`).** Register engine tools in the
  L1–L5 routing with **F1–F7 cost guards** (symbolic execution is expensive and
  must sit behind cost routing — see `CLAUDE.md` model policy):
  - `emulate_stub(va, inputs)` — run a slice, return outputs/decrypted bytes.
  - `resolve_indirect(va)` — concretely resolve an indirect jump/call target.
  - `reach_block(va, target)` — concolic: does input reach `target`? witness?
  Respect the deterministic-output and 128-tool-cap constraints (use `--route`).
  *Test:* tool-registration tests; a routed question exercises a tool.
- **6.5 KB writeback (`python/glaurung/kb/`).** Persist results to the `.glaurung`
  SQLite KB with `set_by` provenance = `auto` (emulation-derived) — **manual
  always wins**: resolved targets become xrefs; decrypted strings become comments/
  strings; computed constants annotate call sites. *Test:* KB round-trip; provenance
  precedence respected.

## Deliverables

- `src/python_bindings/exec.rs`; new CLI commands; `llm/` tool registrations; KB
  writeback wiring.
- Docs: `docs/cli/` entries and `docs/llm/` tool descriptions.

## Exit criteria

- Python API drives the emulator and (if `symbolic`) the explorer; results are
  deterministic across repeated calls.
- Agent tools are registered behind cost guards and routing; a routed question can
  emulate a stub / resolve an indirect target end-to-end.
- Emulation-derived facts land in the KB with correct `auto` provenance that
  manual edits override.
- `uvx pytest`, `ruff`, `ty` all green.

## Notes

This phase can surface the **concrete emulator** (Phases 1–3) before the symbolic
layer (4–5) is finished — `emulate_stub`/`resolve_indirect` are valuable on their
own and unblock Phase 7's highest-ROI applications.
