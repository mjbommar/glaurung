# WP3 symbolic-constant expression origins

Commit `ab265881` makes symbolic constant recovery inspect an expression's
semantic view. Instruction provenance around a literal or one of its casts no
longer hides security-relevant names from the DecBench renderer.

## Observed defect

The helper and rendered-output contracts were added before the repair. Both
were red: an attributed `5` produced no integer value, and an attributed third
argument to `mprotect` rendered without `PROT_READ|PROT_EXEC`. The repair calls
`Expr::semantic()` at each step of the existing cast walk. It does not remove,
move, or rewrite the origin carrier, and unknown constants still fail closed.

## Focused evidence

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`.

```text
cargo test --features python-ext --lib attributed_magic_constant -- --nocapture
RED: 0 passed; 2 failed
GREEN: 2 passed; 0 failed

cargo test --features python-ext --lib ir::named_constants::tests -- --nocapture
8 passed; 0 failed

uv run maturin develop --release
finished release profile; editable wheel installed
```

The real-binary A/B used the existing sample rather than adding a synthetic
fixture:

```text
.venv/bin/glaurung decompile \
  samples/binaries/platforms/linux/amd64/export/native/gcc/O0/suspicious_linux-gcc-O0 \
  --func 0x11c9 --style decbench --format plain

before: local_30 = ptrace(0, 0, 0, 0);
after:  local_30 = ptrace(0 /* PTRACE_TRACEME */, 0, 0, 0);

before: mprotect(local_28, 4096, 5);
after:  mprotect(local_28, 4096, 5 /* PROT_READ|PROT_EXEC */);
```

The exact post-change command piped into `gcc -x c -fsyntax-only -` exits zero.
The change adds comments only, so the numeric call arguments and executable
meaning remain unchanged. No broad suite or corpus sweep was run.
