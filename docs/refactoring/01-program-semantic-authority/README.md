# Mini-project 1: program semantic authority

## Problem

Program-wide facts currently enter analysis through several paths: parsed
images, debug information, format metadata, symbol maps, caller-provided hints,
and decompiler-local environments. `src/program/` is the correct emerging
owner, but `ProgramSession` is not yet the mandatory boundary for all parse,
discovery, type, and cache consumers.

Without one authority, identical facts can acquire different identity,
precedence, or completeness semantics in different callers. Downstream file
splits would merely distribute that inconsistency.

## Target design

```text
bytes/path + budgets
        |
   ProgramSession
    /     |      \
 images  target  ProgramEnvironment
                   |-- symbols + provenance
                   |-- canonical types + conflicts
                   |-- relocations/imports/globals
                   `-- completeness diagnostics
        |
 per-function AnalysisContext views
```

- `ProgramSession` owns expensive parsing and cache keys.
- `ProgramEnvironment` owns immutable, provenance-bearing semantic facts.
- Function analysis receives borrowed/read-only views plus an explicit result
  sink; it must not assemble competing address/name/type maps.
- Conflicting evidence is retained and ranked. Manual evidence remains highest
  priority, and raw facts remain inspectable.

## Proposed module ownership

- `src/program/session.rs`: lifecycle, budgets, cache keys, and service entry
  points only.
- `src/program/image.rs`: immutable bytes, object identity, and format view.
- `src/program/environment.rs`: aggregate API, not format-specific extraction.
- `src/program/types/`: canonical IDs, layouts, provenance, conflicts, and
  DWARF/PDB adapters in separate modules.
- New `src/program/symbols/`: symbol identity, aliases, sources, and resolution.
- New `src/program/diagnostics.rs`: typed incompleteness and evidence conflicts.

## Phases

1. Inventory every construction of symbol/type/address maps and every direct
   object parse in decompiler, analysis, and Python-binding entry points.
2. Add characterization tests proving parse reuse, cache-key sensitivity,
   cross-compilation-unit type conflict retention, and no invented facts.
3. Define stable IDs and provenance/conflict APIs without migrating consumers.
4. Migrate discovery and lifting entry points to a borrowed session context.
5. Migrate debug, relocation, prototype, and naming consumers.
6. Make bypass construction crate-private or delete it; measure parse counts and
   peak retained bytes before and after.

## Exit evidence

- One documented precedence table covers manual, debug, signature, relocation,
  propagated, and heuristic evidence.
- Searches show no production consumer building a competing program-wide
  symbol or type authority.
- Repeated analysis in one session parses each image/debug source once.
- Same-named incompatible layouts remain distinct and diagnosable.
- Focused program tests, all Rust tests, Python integration tests, and the
  decompiler gate pass.

## Stop conditions

Stop a migration if it drops provenance, merges conflicts by name alone,
changes a cache key without a regression test, or makes incomplete evidence
look complete.

