# Error Handling and Logging Guidelines

This document defines how we should design, implement, and use errors and logs across the Rust codebase (and Python bindings). It aligns with industry best practices for library code, security-sensitive tooling, and Python/Rust interop.

## Goals

- Provide clear, actionable errors to callers, with context.
- Separate recoverable classification issues from fatal pipeline failures.
- Keep logs structured, consistent, and low‑noise; enable correlation across a triage run.
- Ensure Python callers get useful exceptions and/or rich error objects.

---

## Error Model

- Layered error types with clear responsibilities:
  - Library/system errors: `GlaurungError` (thiserror) for general operations (I/O, serialization, budgets, timeouts, validation). This is the canonical error for most Rust library APIs.
  - Triage classification issues: `TriageError` (kind + message) are non‑fatal signals that belong in artifacts for downstream consumers and scoring.
  - Triage runtime failures: a distinct type (e.g. `TriageRunError`) for fatal triage pipeline failures (e.g., cannot open/read input, invariants broken) — separate from `TriageError` used as signals.

- Propagation and context:
  - In library APIs, prefer returning `Result<T, GlaurungError>` with variant‑specific context. When converting from lower‑level errors, preserve the original message in the `source` (via `#[from]` or explicit mapping) and add human context in the top‑level variant’s message.
  - In triage, only return `Err(TriageRunError | GlaurungError)` for fatal conditions. For expected/diagnostic issues (parser mismatches, bad magic, short/truncated data, sniffer disagreements), capture them as `TriageError` instances and include in the artifact’s `errors` list.
  - Avoid stringly‑typed `Err(String)` in non‑test code; use typed errors.

- Classification vs. fatal semantics:
  - If a problem does not prevent a useful artifact from being produced (e.g., one parser failed but others succeeded), it is a `TriageError` attached to the artifact and not a hard error.
  - If the input cannot be accessed or basic invariants fail (cannot open file, read bounds violated by our own code, deserialization of our own structures), prefer returning a fatal error.

- Input validation and budgets:
  - Validate inputs early, with specific error kinds (e.g., `InvalidInput`, `BadMagic`, `ShortRead`).
  - Use timeouts/budgets to prevent hangs or excessive resource use. Timeouts should return `GlaurungError::Timeout { seconds }` and be logged at error level once.

- Python interop:
  - Map `GlaurungError` to appropriate Python exceptions (already done for IO/Timeout/ValueError; extend as needed). Avoid raising `PyRuntimeError` for known error kinds.
  - For triage calls, prefer returning `TriagedArtifact` with an `errors` list. If a fatal condition occurs, raise a specific Python exception (mapped from `GlaurungError | TriageRunError`).
  - Consider exporting a Python exception class for triage runtime failures for more precise handling.

- Testing:
  - Assert on error kinds and messages (stable, compact), not on formatted debug dumps.
  - Avoid `unwrap()`/`expect()` in non‑test code; propagate errors.

---

## Logging Model

- Use `tracing` everywhere (no `println!` in library code):
  - Prefer structured logs with fields: `info!(format = ?fmt, arch = ?arch, bits, ... , "Validated header")` instead of interpolated debug dumps.
  - Use spans to correlate work within a single triage run. At the top entry points (`analyze_path`, `analyze_bytes`), create a span with `triage_id`, `path`, and `size_bytes`. Propagate span context into sub‑modules.

- Log levels and intent:
  - error: a real failure that returns an error or aborts the current operation.
  - warn: unexpected but recoverable anomalies worth attention (e.g., conflicting strong signals).
  - info: high‑level lifecycle events (start/finish of a run) and significant state transitions.
  - debug: normal diagnostics in hot paths (parsers, sniffers, header checks, entropy passes, bounded I/O limits reached).
  - trace: very chatty internals (byte offsets, parsed counts), usually off by default.

- Noise control:
  - Avoid logging in tight loops unless guarded by level checks or sampled.
  - Do not log at error/warn for expected negative outcomes (e.g., a parser failing as part of a multi‑parser strategy) — that is `debug`.
  - Rate‑limit repetitive warnings if needed.

- Initialization:
  - Provide a single, idempotent initialization (`init_tracing`) and a JSON variant. Allow configuration of log level/filter (e.g., `RUST_LOG` or an explicit level parameter) from both Rust and Python APIs.
  - Prefer JSON format for machine ingestion in CLI/CI; text for local dev.

- Privacy and safety:
  - Never log unbounded buffers. When logging snippets, truncate and hex‑encode. Do not log secrets or user PII.
  - Prefer numeric counts/lengths over raw content unless explicitly needed and safe.

---

## Conventions and Patterns

- Naming: error kinds and signal names use snake_case; logs use consistent field names (`path`, `size_bytes`, `triage_id`, `format`, `arch`, `bits`, `endianness`, `parser`, `confidence`).

- Construction helpers:
  - Use `TriageError::new(kind, message)` for classification issues, and ensure message includes succinct context (e.g., offsets, expected vs actual).
  - Use `ConfidenceSignal::create(name, score, notes)` with stable names and brief `notes`.

- Instrumentation:
  - Add `#[tracing::instrument(skip(data, reader))]` to top‑level functions (`analyze_path`, `analyze_bytes`, parser/validator entry points). Avoid capturing large buffers in spans.

- Python CLI:
  - Initialize logging explicitly and accept `--json` and `--level` to set format and verbosity.
  - On error, prefer structured JSON emission with an `error` object when `--json` is set.

---

## Checklists

### When adding/altering a function

- [ ] Return a typed error (`GlaurungError` or `TriageRunError`) for fatal failures.
- [ ] Convert recoverable issues into `TriageError` and append to the artifact or result set.
- [ ] Add `instrument` and structured logs at appropriate levels; avoid string interpolation when fields can be used.
- [ ] Ensure large or sensitive data is not logged.

### When adding a parser/sniffer

- [ ] Do not log at error/warn for mismatches that are part of normal operation.
- [ ] Convert mismatches to `TriageErrorKind::ParserMismatch` or a more precise kind.
- [ ] Provide low‑weight `ConfidenceSignal`s with stable names.

### Python bindings

- [ ] Map typed errors to specific Python exceptions (not generic `RuntimeError`).
- [ ] Keep artifact `errors` rich and accessible; expose typed accessors.
- [ ] Allow caller to configure logging level/format.

---

## References (in code)

- Error types: `src/error.rs` (GlaurungError), `src/core/triage.rs` (TriageError/TriageErrorKind)
- Logging: `src/logging.rs`
- Triage entry points: `src/triage/api.rs`
- I/O and budgets: `src/triage/io.rs`, `src/timeout.rs`
- Parsers/headers/sniffers: `src/triage/*`

---

## Near‑Term Improvements (high level)

See the companion fix list in the PR/issue for specific locations. Highlights:

- Introduce a `TriageRunError` distinct from `TriageError` and use it (or `GlaurungError`) as the `Err` type of triage entry points.
- Switch some `warn!`s to `debug!` where the condition is expected under budget limits.
- Add `#[instrument]` spans and a `triage_id` correlation field across the triage pipeline.
- Prefer structured logs over `{:?}` dumps in hot paths.
- Expose a Python API to set log level (not just JSON vs text).

This document should be treated as the source of truth for future work on error handling and logging.

