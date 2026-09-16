# Runtime analysis sample corpus

This corpus contains small, real C executables for runtime acquisition and
static/runtime correlation tests. Each program accepts `good` or `bad` as its
first argument. The optional second argument is a numeric parameter. Programs
that finish normally print one stable `RESULT` line.

`manifest.toml` is authoritative for category and expected outcome. Build and
run it with:

```bash
uv run python tools/runtime_sample_harness.py list
uv run python tools/runtime_sample_harness.py build --compiler gcc --opt O2 --link pie
uv run python tools/runtime_sample_harness.py matrix
uv run python tools/runtime_sample_harness.py run --sample normal_open_file --scenario good
uv run python tools/runtime_sample_harness.py live --sample memory_struct_field_overwrite --scenario bad
uv run python tools/runtime_sample_harness.py live --sample crash_null_write --scenario bad --checkpoint entry
uv run python tools/runtime_sample_harness.py core --sample crash_null_write --scenario bad
```

Build products and captures live below `target/runtime-samples` by default and
are not source artifacts. `live` launches with
`GLAURUNG_RUNTIME_CHECKPOINT=1`, waits for the sample's `SIGSTOP`, records
`/proc` metadata, and leaves a normalized artifact before terminating the
process. `--checkpoint entry` stops in a constructor before `main`, so even a
crashing path can be inspected live; the default `exit` checkpoint observes
normal and silent-corruption cases after their principal behavior. `core` uses
a private working directory and reports whether the host's
core policy produced a readable core; it never claims success when the kernel
redirected or suppressed the dump.

The default matrix is GCC and Clang, `-O0` and `-O2`, and PIE and non-PIE
dynamic linking. Repeat `--compiler`, `--opt`, or `--link` to select other
lanes; `--link static` is available when the host has static libc development
files. The matrix executes both scenarios and checks their process-level
exit/signal oracles.

Live artifacts never store environment values in plaintext. They record each
variable name, value length, and SHA-256 digest so runs can be compared without
copying credentials into an artifact.

The programs intentionally contain unsafe and undefined behavior. Never run
them outside the harness or against valuable paths, credentials, or services.
