# Errors and logging

> **Status: maintained developer guide.** This page describes the APIs that
> exist today. Proposed error types and logging controls are called out as gaps,
> not documented as shipped behavior.

Use typed errors to preserve failure semantics, and use structured logging to
explain execution without exposing target contents. The live definitions are
in `src/error.rs`, `src/core/triage/errors.rs`, `src/logging.rs`, and
`python/glaurung/logging.py`.

## Rust error boundaries

`GlaurungError` is the shared framework error in `src/error.rs`. It covers
invalid formats and inputs, parse offsets, timeouts, resource exhaustion,
unsupported architectures, I/O, serialization, address and symbol failures,
patterns, triage, and internal failures. Use the narrow subsystem error already
present when one exists; convert to `GlaurungError` at a shared API boundary
instead of erasing the cause into `String`.

The PyO3 conversion currently maps:

- `Io` to `PyIOError`;
- `Timeout` to `PyTimeoutError`;
- `InvalidInput` and `InvalidFormat` to `PyValueError`; and
- every other variant to `PyException`.

Do not document a more specific Python exception until the conversion actually
implements it. Tests should assert the stable variant or Python exception type
and the useful part of the message, not a full debug rendering.

Triage has a second, diagnostic boundary in
`src/core/triage/errors.rs`. `TriageErrorKind` classifies `ShortRead`,
`BadMagic`, `IncoherentFields`, `UnsupportedVariant`, `Truncated`,
`BudgetExceeded`, `ParserMismatch`, `SnifferMismatch`, and `Other`.
`TriageError` stores that kind plus an optional message. These errors belong in
the returned artifact when analysis can still produce useful partial results.
Callers must inspect artifact errors and budget indicators even when the call
itself succeeds.

`TriageRunError` does not currently exist. Fatal triage failures use the result
types exposed by the current entry point; do not write code or documentation
that assumes a separate runtime-error class.

When adding or changing Rust analysis code:

- validate lengths, offsets, variants, and resource budgets before use;
- return the narrowest typed error available and preserve the lower-level
  source where practical;
- attach expected parser disagreement or truncation to the artifact when useful
  analysis can continue;
- avoid `unwrap()` and `expect()` outside tests; and
- test malformed, truncated, and budget-limited real fixture paths as well as
  the successful path.

## Python error boundaries

Python APIs should preserve native exception types rather than catching every
failure and raising a generic `RuntimeError`. CLI commands should translate an
exception into a concise diagnostic and a nonzero exit status at the command
boundary. Library APIs should not print errors or terminate the process.

When a triage artifact is returned, treat its diagnostic errors as data:

```python
from pathlib import Path

from glaurung import triage

artifact = triage.analyze_path(
    str(Path("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"))
)
for diagnostic in artifact.errors:
    print(diagnostic.kind, diagnostic.message)
```

Use a checked-in real sample for examples and integration tests. Unit tests may
construct small values only when the behavior under test is the value model,
not binary parsing or analysis.

## Rust tracing

Rust library code uses `tracing`; do not use `println!` for diagnostics.
`src/logging.rs` exposes `init_tracing()` for text output and
`init_tracing_json()` for JSON output. Both honor `RUST_LOG`, default to `info`,
and share a process-global `Once`. The first initializer called therefore fixes
the native output format for that process; later calls are ignored.

The Python extension exposes `init_logging(json: bool)` and `log_message(...)`.
The native initializer chooses JSON versus text but does not accept a level;
set `RUST_LOG` before initialization to control the Rust filter.

Use structured fields with stable names, for example:

```rust
tracing::info!(
    path = %path.display(),
    size_bytes = size,
    format = ?format,
    "analysis completed"
);
```

Use levels consistently:

- `error` for a failure returned to the caller or an aborted operation;
- `warn` for an unexpected but recoverable condition needing attention;
- `info` for bounded lifecycle events and significant transitions;
- `debug` for normal parser, budget, and decision diagnostics; and
- `trace` for deliberately chatty internals.

Expected negative probes in a multi-parser strategy normally belong at `debug`,
not `warn` or `error`. Avoid logs inside hot loops unless they are guarded or
bounded. Never log full target buffers, credentials, model secrets, or other
sensitive input. Prefer offsets, counts, lengths, hashes, and bounded summaries.

`src/triage/api.rs` creates a `triage` span containing `triage_id`, `path`, and
`size_bytes`. Enter or instrument child work so these fields remain available;
skip byte buffers and readers when using `#[tracing::instrument]`.

## Python structured logging

`python/glaurung/logging.py` exposes `configure_logging`, `get_logger`, and
context helpers. `configure_logging(level=..., json_output=...)` configures
Python `logging` and `structlog`, then initializes native logging when the
extension is available.

```python
from pathlib import Path

from glaurung.logging import configure_logging, get_logger

configure_logging(level="DEBUG", json_output=False)
logger = get_logger(__name__)
target = Path("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2")
logger.info("analysis_started", path=str(target), size_bytes=target.stat().st_size)
```

The main CLI does not currently expose global `--level` and logging-format
flags. Configure the library API directly or set `RUST_LOG` before native
initialization; do not advertise unimplemented CLI switches.

## Focused validation

Run the narrow checks while editing these boundaries:

```bash
cargo test error::tests
cargo test logging::tests
uv run pytest python/tests/test_triage_types.py -q
```

Then run the repository-wide Rust, Python, formatting, lint, and type gates from
`CLAUDE.md` before claiming the whole checkout is green. A focused pass is not a
substitute for those broader gates.

## Known gaps

- Most `GlaurungError` variants still map to the generic Python `PyException`.
- `TriageRunError` does not currently exist.
- Native tracing is process-global and cannot change format after its first
  initialization.
- Python logging accepts a level, while the native filter is controlled through
  `RUST_LOG`.

Treat these as implementation constraints. If a change closes one, update the
source, focused tests, bindings or stubs, and this guide in the same change.
