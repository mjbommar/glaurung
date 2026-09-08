# WP3 AAPCS VFP setup identities

Status: landed in `d7dfcf9f` on `agent/wp5-next-switch`.

## Result

Pure hard-float AAPCS call setup now classifies core-register, VFP-register, and
unrelated destinations from authoritative SSA identity candidates. It no
longer trusts `s0#version`, `d0#version`, or `r0#version` display spellings.

Several coalesced identities are accepted only when every candidate has the
same storage classification. Cross-bank ambiguity fails closed. An opaque
value proved to occupy `s0` is folded, while a displayed `s0#2` proved to
occupy `r0` is treated as core-bank setup and cannot trigger the pure-VFP
recovery. The no-sidecar compatibility path retains name-based classification.

## Focused evidence

- Exact regression: `pure_vfp_setup_uses_exact_identity_not_display_spelling`
  passed (`1 passed`, `4476 filtered out`).
- Owning AAPCS module: `cargo test --features python-ext --lib
  ir::call_args::aapcs -- --nocapture` passed (`5 passed`, `0 failed`, `4472
  filtered out`).
- Native extension: `uv run maturin develop` completed, then
  `uv run python tools/build_guard.py` reported the extension fresh.
- Direct fixture: `uv run python tools/dectest.py
  172_float_double_widths:armv7:O0:single_precision_horner --show` selected
  exactly one of 3,304 lanes and reported no regression.

No full Rust suite, Python suite, fixture sweep, DecBench run, or Joern run was
used for this increment.

## Remaining WP3 work

WP3 remains open. AAPCS outgoing stack-area classification and the cdecl stack
reader still contain display-name storage checks.
