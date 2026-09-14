# Standalone source-analysis extraction

> **Kind:** plan · **Status:** proposed

Extract Glaurung's native C source-analysis front end into an independently
versioned Rust crate and Maturin/PyO3 package. Glaurung must become a downstream
consumer; the outcome must not be a maintained second copy.

This plan does not authorize publication or name reservation. Registry checks
below were made on 2026-09-14 and can become stale.

## Name

Use **Cindergraph** as the working name:

| surface | proposed value |
|---|---|
| repository and Rust core crate | `cindergraph` |
| PyO3 binding crate | `cindergraph-python` |
| PyPI distribution and Python import | `cindergraph` |
| private extension | `cindergraph._native` |

It is independent of Glaurung and does not falsely promise a code property
graph or drop-in Joern implementation. Refreshed exact-name PyPI and crates.io
API requests both returned HTTP 404 on 2026-09-14. A general web search found
no conflicting software project for this name; that is only a preliminary
screen. A 404 does not prove a name can be registered. This is neither
reservation nor trademark clearance; repeat registry,
repository-host, domain and trademark checks immediately before publication.

Fallbacks, in order:

1. `glaurung-source` / `glaurung_source`: clearest provenance and PyPI 404,
   but it looks like a Glaurung plugin.
2. `wyrmgraph`: distinctive and PyPI 404, but less descriptive.
3. `cairn-c` / `cairn_c`: C-specific and PyPI 404, but awkward if another
   language front end is added.
The three fallbacks also returned 404 from both registries. Reproduce the
exact-name screen with the following read-only requests, replacing NAME:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/NAME/json
curl -s -o /dev/null -w '%{http_code}\n' -A glaurung-extraction-research https://crates.io/api/v1/crates/NAME
```

Reject `codeanatomy`: despite registry 404s, an existing
[LaTeX software package](https://github.com/hpb-htw/codeanatomy) uses the name.
Reject `semforge`: an [active product](https://semforge.online/) already uses it.
Reject `codeweave`: it exists on PyPI. Avoid names containing Joern: this has a
different data model and query surface, so that would create compatibility and
trademark expectations it does not meet.

## Scope and boundary

The live inspection baseline is Glaurung commit
`0892552157be6bd9267007231419ff6606a2dd38`, plus uncommitted changes in
source analysis and unrelated decompiler files. This identifies the inspected
checkout, **not** an approved extraction snapshot. In particular,
`src/python_bindings/source_metrics.rs` contains both portable analyses and
solver-backed bindings: it must be split by responsibility, not copied whole.

The useful boundary is larger than `src/csource/joern/`: its parity CFG is a
projection over the parser and general CFG.

Version 0.1 includes:

- `src/syntax/`: tokens, spans, diagnostics, trees, CFG, dominance, GED and
  graph serialization;
- `src/csource/{lex,parse,normalize,cfg}`: tolerant C/decompiler-C front end;
- `src/csource/metrics/`: function metrics;
- `src/csource/dataflow/` and `export.rs`: bindings, reaching definitions,
  dead stores, summaries, slices, and AST/CFG/DDG/CDG/PDG export;
- `src/csource/joern/`, renamed `parity`: deterministic DecBench GED shape;
- the useful facade from `python/glaurung/{source,_source_files,source_cfg}.py`.

Version 0.1 excludes these Glaurung-coupled areas:

- `csource/lower`, which uses Glaurung LLIR and its differential harness;
- `csource/feasibility` and `csource/equiv`, which use LLIR, execution and
  symbolic solver selection;
- `.glaurung` knowledge-base persistence and DecBench tooling.

Those remain Glaurung integrations until narrow engine-independent traits
exist. This ships the native functionality used in place of Joern plus the
general source-analysis API, without pulling a reverse-engineering framework
into every consumer.

### Concrete dependency and test inventory

The inspected portable Rust boundary uses `regex` for normalization and
`serde_json` for graph export, in addition to the standard library and its own
`syntax`/`csource` modules. Start with those production dependencies; do not
inherit Glaurung's Cargo dependency list. Confirm this inventory by compiling
the extracted core, since textual inspection is not a dependency-closure proof.
PyO3 remains a binding-only dependency; the Python facade can use the standard
library with NetworkX supplied by an optional `graphs` extra.

Move the portable registrations from both
`src/python_bindings/source_metrics.rs` and
`src/python_bindings/source_cfg.rs`. The latter supplies parity CFGs and the
scoreable-name filter and is easy to miss when copying only metrics bindings.
The existing file-oriented compatibility implementation lives in
`python/glaurung/_source_files.py`; `compat/pyjoern.py` is the proposed new
location, not an existing Glaurung module.

Initial Python characterization coverage should come from
`test_source_metrics.py`, `test_source_metrics_decompiled.py`,
`test_source_cfg_provider.py`, `test_source_graph.py`,
`test_source_dataflow.py` and `test_source_files.py`. Classify individual tests
and their fixture imports before moving them. Keep solver-backed
`test_source_feasibility.py` downstream and external Joern comparisons opt-in.
Several Rust corpus tests currently return early when repository-relative
fixture directories are missing; packaging must replace that behavior with a
required, bundled corpus and an asserted nonzero population.

## Target layout

Use a two-crate workspace in a separate repository:

```text
cindergraph/
├── Cargo.toml
├── crates/cindergraph/             # pure Rust rlib
├── crates/cindergraph-python/      # thin PyO3 cdylib
├── python/cindergraph/
│   ├── __init__.py
│   ├── source.py
│   ├── compat/pyjoern.py
│   ├── _native/__init__.pyi        # generated
│   └── py.typed
├── tests/
├── python/tests/
├── pyproject.toml
├── README.md
├── LICENSE
└── NOTICE
```

The core must test without Python, Glaurung, Java, a solver or a C compiler.
PyO3 belongs only in the binding crate; Maturin enables `extension-module`, not
a Cargo default. Configure the recommended mixed layout:

```toml
[tool.maturin]
manifest-path = "crates/cindergraph-python/Cargo.toml"
python-source = "python"
module-name = "cindergraph._native"
features = ["pyo3/extension-module"]
```

Python owns paths, warnings, dataclasses and optional NetworkX conversion. Rust
owns parsing, analysis, deterministic ordering and wire formats. Keep both
crates on the same version; Python users see only the `cindergraph`
distribution.

## API contract

Do not expose today's internal module layout as the permanent API. Start with
owned result types and a small Rust facade:

```rust
pub fn analyze(source: &str, options: &AnalyzeOptions) -> SourceReport;
pub fn normalize(source: &str, dialect: Dialect) -> NormalizedSource;
pub fn export(source: &str, repr: GraphRepr, format: GraphFormat)
    -> AnalysisResult<Vec<NamedGraph>>;
pub fn parity_cfgs(source: &str) -> BTreeMap<String, ParityCfg>;
pub fn reaches(source: &str, query: ReachabilityQuery) -> Reachability;
```

Partial or malformed C returns partial results and diagnostics, never a panic.
Reachability stays `Yes | No | Unknown(reason)`; unknown must not become false.
Serialized collections have deterministic order.

The signatures above are proposed, not existing callable APIs. Before freezing
them, specify UTF-8 byte spans versus character offsets, coordinates after
normalization, duplicate function-name handling, dense graph-local IDs,
parser recovery diagnostics, and analysis completeness. Preserve these in both
language bindings; convenience APIs must not silently erase uncertainty.
Keep general CFGs used for metrics distinct from parity projections.

The Python facade should expose `analyze`, `analyze_path`, `normalize`,
`export_graphs`, `export_path`, `functions`, `features`,
`control_flow_graphs`, `data_flow`, `control_dependence`, `backward_slice`,
`call_summaries`, and `reaches`. Put migration helpers under
`cindergraph.compat.pyjoern`; continue to refuse unsupported JIL and option
semantics instead of fabricating results.

Rename Rust `joern` to `parity` before 1.0. Document `ParityCfg` narrowly as
the properties consumed by DecBench GED. A deprecated re-export may ease the
Glaurung migration but should not become stable standalone vocabulary.

## Work plan

### 0. Freeze contract and provenance

1. Record the extraction base commit in a dedicated clean worktree. The current
   checkout has active modifications inside this boundary and is unsafe as an
   extraction source until their owner resolves them.
2. Inventory Rust public items, PyO3 registrations and Python APIs; classify
   each as 0.1, compatibility-only, Glaurung integration or private.
3. Copy relevant tests first and pin outputs at the base commit.
4. Audit file history, dependencies and fixture provenance. Preserve
   Apache-2.0 notices and third-party attribution. Prefer a history-preserving
   filtered split over a squashed import.

Exit: a committed manifest of source files, tests, APIs and source commit.

### 1. Extract the Rust core without semantic edits

1. Move `syntax` and the dependency-closed 0.1 `csource` modules.
2. Fix namespaces mechanically, then add the facade separately.
3. Omit/gate lowering, feasibility and equivalence; move corpus helpers to dev
   dependencies and minimize production dependencies.
4. Start at Glaurung's Rust 1.88 floor. Lower the MSRV only by tested decision.
5. Use `#![forbid(unsafe_code)]` if the extracted boundary permits it.

Gates:

```bash
cargo test -p cindergraph --all-features
cargo check -p cindergraph --no-default-features
cargo clippy -p cindergraph --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo package -p cindergraph --allow-dirty
```

Inspect `cargo package --list` and test the generated crate archive.
`--allow-dirty` is for extraction experiments only; the release gate must run
without it from the approved clean commit. Bundle every required test corpus
inside the crate package: tests must fail if that corpus is missing rather
than silently exercising zero files.

### 2. Add the thin PyO3 package

1. Bind only the Rust facade and return owned values; do not expose arena
   lifetimes or duplicate analysis in bindings.
2. Use `Python::detach` for substantial analyses as today.
3. Port wrappers into the new namespace, generate stubs from the extension,
   compare them in CI, and ship `py.typed`.
4. Keep NetworkX optional and lazily imported.
5. Preserve Python `>=3.12`. Trial `abi3-py312`; adopt it only after the same
   wheel passes on CPython 3.12, 3.13 and 3.14.

Do not infer PyPy or free-threaded CPython support from the stable-ABI tag;
those need separate support decisions and test lanes. Preserve `compare` and
the file-discovery helpers where they are independent of Glaurung, and keep
`path_feasibility` / `source_findings` in the downstream integration.

Gates are `maturin develop`, Python tests, Ruff format/check, `ty check`, and
`maturin build --release`. Install the wheel with the checkout absent from
`sys.path` into clean supported environments and verify imports, stubs,
optional-dependency errors, diagnostics and all examples.

### 3. Invert the Glaurung dependency

1. Before publishing, point Glaurung at the new core by path dependency.
2. Keep LLIR lowering, solver features, KB writes and DecBench tools in
   Glaurung.
3. Make `glaurung.source` a compatibility facade for one deprecation window.
4. Delete Glaurung's implementation only after both projects pass against the
   same core commit. Never maintain vendored and crate copies in parallel.

Rust integrations must use re-exported core types, not separately compiled
copies of `Span`, trees or CFG types. For Python, delegate portable calls to
the standalone distribution while retaining Glaurung's solver-backed calls.
Pin compatible Rust/Python core versions and verify normalized graph/schema
equivalence so the two extensions cannot silently disagree.

Run Glaurung's focused source suites and required Rust/Python gates. Joern and
DecBench remain opt-in and may run only when explicitly requested; there can be
no autonomous upstream interaction.

### 4. Release engineering

1. Pin release-supported Maturin/PyO3 versions and use a reproducible CI lock.
   The inspected repository uses PyO3 0.26 and Maturin `>=1.9,<2.0`.
   Extract against that baseline first; handle upgrades as a separate tested
   change. A lockfile aids repeatability but does not alone guarantee
   byte-reproducible wheels.
2. Build and artifact-test an sdist plus manylinux x86-64/AArch64, macOS
   x86-64/arm64 (or tested universal2), and Windows x86-64 wheels. Add musllinux
   x86-64/AArch64 only if Alpine is declared supported.
3. Inspect wheel tags and dynamic libraries. Version 0.1 must need no Java,
   solver, Graphviz, compiler or nonstandard system library at runtime.
4. Verify the sdist builds in a clean documented environment.
5. Publish a release candidate to TestPyPI and install/test that exact artifact.
6. Use PyPI Trusted Publishing from a protected GitHub release environment,
   signed tags, hashes and attestations; do not keep a long-lived API token.
7. Publish the Rust core first. Once crates.io resolves it, build the binding
   against that exact version, then publish matching PyPI artifacts.

Start at `0.1.0`. Do not call it 1.0 until Glaurung consumes a released version,
the facade survives a deprecation cycle, and serialized graph schemas have
explicit versions.

### 5. Consider solver-backed companion functionality

After 0.1, design a narrow semantic IR and/or bounded `PathOracle` trait with
Glaurung as the first downstream implementation. Do not pull the whole LLIR and
symbolic engine into the core. Evidence should decide whether this becomes a
`cindergraph-semantic` crate or stays in Glaurung.

## Evidence and release acceptance

Before moving code, capture release-profile baselines on checked-in C fixtures:
parse-only, metrics, general/parity CFG, dataflow, summaries and serialization.
Record fixture hashes, function/input counts, toolchain, commit and build
profile. Compare identical old/new inputs with warmups and repeated batches;
report median time, peak memory and artifact size. Separate Python call and
serialization cost from Rust analysis. Set regression budgets after measuring
baseline variance, not from an invented target. Exercise long functions,
many short functions, malformed input and recursive call graphs separately.

| claim | required evidence |
|---|---|
| parser robustness on tested inputs | junk/truncated/mixed-validity inputs yield partial results and diagnostics without panic; finite tests do not prove totality |
| behavior did not drift | copied Rust and Python characterization tests pass across the old/new boundary |
| output is deterministic | repeated JSON/DOT/GraphML/Mermaid is byte-identical |
| parity is preserved | committed offline Joern-derived fixtures pass at a fixed denominator |
| no hidden runtime | clean offline wheel analyzes C without Java, Graphviz or a compiler |
| packages are real | tests run from generated `.crate`, wheel and sdist artifacts, not the checkout |
| implementation is singular | Glaurung lock/source metadata identifies the released core; no copy remains |

The first public release additionally requires complete license/NOTICE and
fixture provenance; generated stubs and `py.typed` in wheels; every declared
platform green; TestPyPI verification; human-approved registry reservation
under 2FA; and release wording of "targeted native C source analysis", not full
Joern or CPG compatibility.

## First implementation handoff

Approve the working name and an extraction snapshot first. Then deliver a
local, unpublished Rust core with its fixture corpus and characterization
tests; add Python packaging only after that core stands alone. The critical
path is snapshot/provenance → core extraction → bindings and artifact tests →
Glaurung migration → approved publication. Registry ownership, platform
support and the stable-ABI trial are explicit release decisions, not reasons
to mix semantic redesign into the initial move.

This document is research and planning, not evidence that extraction, package
builds, benchmarks or downstream migration have passed. No code movement or
publication is part of this planning change.

## Research basis

- Maturin's mixed-project layout and private extension guidance:
  <https://www.maturin.rs/project_layout.html>.
- PyO3 building/distribution and stable-ABI guidance:
  <https://pyo3.rs/v0.26.0/building-and-distribution.html> (the inspected version).
- Maturin wheel distribution and platform tooling:
  <https://www.maturin.rs/distribution.html>. Use Maturin's own CI tooling for
  this Rust-only extension; do not introduce a second wheel orchestrator unless
  the platform matrix requires it.
- PyPI distribution-name normalization (hyphens, underscores and dots are not
  independent reservations):
  <https://packaging.python.org/en/latest/specifications/name-normalization/>.
- PyPI Trusted Publishing uses short-lived identity-based credentials:
  <https://docs.pypi.org/trusted-publishers/>.
- PyPA recommends `cibuildwheel` for multi-platform extension wheels and
  Trusted Publishing for supported CI:
  <https://packaging.python.org/en/latest/guides/tool-recommendations/>.
- PyPA recommends publishing an sdist alongside wheels:
  <https://packaging.python.org/en/latest/discussions/package-formats/>.
