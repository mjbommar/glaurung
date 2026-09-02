# Mini-project 4: native/Python API boundary

> **Kind:** record · **Date:** 2026-08-13

## Problem

`src/python_bindings/ir.rs` and `src/python_bindings/analysis.rs` contain both
PyO3 translation and analysis orchestration. This allows Python surface needs
to influence native semantic ownership and makes it difficult to test the Rust
application API independently.

The package root also eagerly exports a broad native surface and performs
Python-side convenience behavior. That is useful compatibility, but it needs a
clear boundary from authoritative analysis.

## Target design

```text
Rust domain model -> Rust application services -> transport DTOs -> PyO3
                                                       |
                                                Python typed facade
```

- Domain and application modules never import PyO3.
- Binding modules validate Python inputs, call one application service, and
  convert a result/error into stable DTOs.
- DTOs carry provenance, completeness, and diagnostics; conversion cannot
  silently omit unsupported variants.
- Python convenience code composes public services but does not repair or
  reinterpret native facts.

## Proposed ownership

- `src/decompile/service.rs`: native decompilation request/result contract.
- `src/analysis/service.rs`: native discovery/xref/analysis requests.
- `src/python_bindings/ir/`: request parsing, result types, registration.
- `src/python_bindings/analysis/`: the same three concerns.
- `python/glaurung/api/`: stable typed Python-facing services.
- Package-root exports become compatibility aliases with import-cost tests.

## Phases

1. Inventory all `#[pyfunction]`, `#[pymethods]`, registration, and orchestration
   code in the two large binding files.
2. Add Rust-only integration tests for the service calls currently reachable
   only through Python.
3. Define versionable request/result DTOs and exhaustive error conversion.
4. Extract one vertical slice at a time: discovery, lifting, decompilation,
   diagnostics, then batch operations.
5. Split registration from conversion and delete duplicate orchestration.
6. Add import-time/RSS baselines and compatibility tests for public imports.

## Exit evidence

- `rg 'pyo3' src --glob '*.rs'` finds PyO3 only in the crate root and binding
  modules.
- Rust services can be tested without `python-ext`.
- Binding functions contain no pass sequencing, file parsing, or semantic
  recovery policy.
- Native errors map to stable, specific Python exceptions or typed incomplete
  results.
- Public Python API compatibility and `.pyi` coverage are tested.

## Stop conditions

Reject migration that converts errors to empty collections, exposes internal
mutable models as API stability promises, or adds a second Python-only analysis
pipeline.

