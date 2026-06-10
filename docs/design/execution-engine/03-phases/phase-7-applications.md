# Phase 7 — Applications

**Goal:** wire the engine into end-to-end analyses that measurably improve
Glaurung's output on real binaries. Each application is independently shippable
and rides on whatever engine subset exists.

**Feature gate:** varies per application.

## Applications (ranked by value-to-effort)

### 7.1 Concrete string / payload decryption *(needs: Phase 1–3)*
Detect self-contained decode stubs (small loops over a buffer with xor/add/sub +
a key), emulate them over the encrypted bytes, recover plaintext, write results to
the KB as strings/comments.
- *Heuristic seeding:* reuse `strings`/entropy + CFG loop detection to nominate
  stubs.
- *Test:* on a real packed/obfuscated `samples/` binary, recover known plaintext
  strings; assert against a fixture of expected decrypted values.

### 7.2 Indirect control-flow resolution *(needs: Phase 1–3, light Phase 4)*
Concretely (or concolically) resolve `call rax` / jump tables / vtable dispatch
that static CFG leaves as "indirect"; feed resolved edges back into
`src/analysis/cfg.rs` and the KB as xrefs.
- *Reuse:* existing `jump_table.rs`, `vtable.rs`, `xrefs.rs`.
- *Test:* CFG completeness improves on a fixture with known indirect targets
  (count resolved edges; compare to ground truth).

### 7.3 Computed-constant & API-hash resolution *(needs: Phase 1–3)*
Emulate API-hashing resolvers (common in shellcode/malware) to map hashes →
imported function names; recover stack cookies / seeds.
- *Test:* a real API-hashing sample resolves to the expected import set.

### 7.4 IOCTL sink-finding with witnesses *(needs: Phase 4–5)*
The symbolic successor to `ioctl_taint`: nominate candidate sinks via the static
pass, confirm reachability with directed concolic execution, emit a concrete
IOCTL input witness, and report it.
- *Reuse:* `src/analysis/ioctl_taint.rs` taxonomy + `os/windows.rs` IRP model.
- *Test:* on a known-vulnerable driver fixture, produce a witness that drives the
  dispatcher to the sink; validate the witness by concrete replay.

### 7.5 Opaque-predicate / dead-code detection *(needs: Phase 4)*
Use the solver to prove a branch condition constant under its path constraint →
flag opaque predicates and unreachable code for the decompiler/deobfuscator.
- *Test:* a fixture with a known opaque predicate is flagged; a genuine branch is
  not.

### 7.6 LLM-driven micro-experiments *(needs: Phase 6)*
Let the agent pose "what does this function compute for input X" / "what input
reaches block Y" as routed, cost-guarded tool calls during interactive analysis.
- *Test:* an agent workflow test that uses `emulate_stub`/`reach_block` and
  produces a correct answer on a fixture.

## Cross-cutting deliverables

- A **regression scorecard** entry (`uv run python -m glaurung.bench`): measure
  strings-recovered and indirect-edges-resolved on a fixed sample set, so engine
  improvements show up as numbers.
- `docs/campaigns/` worklog entries documenting each application run on real
  samples (per the existing campaign-log convention).

## Exit criteria

- At least 7.1 (string decryption) and 7.2 (indirect resolution) run end-to-end on
  real `samples/` binaries and measurably improve KB/CFG coverage on the
  scorecard.
- 7.4 (IOCTL witnesses) demonstrated on a vulnerable-driver fixture once Phase 5
  lands.
- All applications respect provenance (`auto`, manual wins) and determinism.

## Notes

These applications are the *justification* for the whole effort (see
[`../00-motivation-and-goals.md`](../00-motivation-and-goals.md)). 7.1–7.3 need
only the concrete emulator, so they can ship after Phase 3 and deliver value long
before the symbolic layer is complete — front-load them.
