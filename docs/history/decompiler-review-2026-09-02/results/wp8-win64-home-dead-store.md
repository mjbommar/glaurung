# WP8 Win64 home-slot dead-store evidence

Date: 2026-09-04

## Defect

The committed clang-cl PE32+/PDB fixture begins `record_value` with
`push rax; mov [rsp], rcx`. The first instruction reserves stack space; the
second homes the first Win64 parameter into that space. Stack promotion
previously rendered both writes as source state:

```c
long local_8 = ret;
local_8 = (long)arg0;
```

Nothing observes the pushed value. Rendering it as an initializer manufactured
an undefined read and made an otherwise verified function look unsound.

## Change

`src/ir/dead_stores.rs` now removes a promoted-stack write only when the next
non-comment statement overwrites the identical slot at the identical width.
The rule declines across control flow, for partial-width overwrites, when the
second value reads the slot, or when the first expression may be observable.
It recurses through already structured regions and retains best-effort output
when it cannot prove the local overwrite.

The real fixture test in `python/tests/test_pdb_type_recovery.py` requires the
synthetic local to disappear and requires the render verifier to report no
unverified `record_value` result.

## Validation

Base revision: `ceefd4ca78f930701fa8787c4c5d542eb4fb4df8`. The extension was
rebuilt from both sides of the A/B comparison.

```text
cargo test --features python-ext ir::dead_stores::tests --lib -- --nocapture
36 passed; 0 failed

cargo test --features python-ext
3,785 library tests passed; 4 ignored; all ordinary integration targets passed;
2 doc tests passed; 1 ignored

uv run maturin develop
completed successfully

uv run pytest python/tests/test_pdb_type_recovery.py -q
12 passed; 0 failed

GLAURUNG_VERIFY_DEFS=1 uv run python -m glaurung.cli decompile \
  tests/pdb_types/types.dll --func record_value --style decbench --no-color \
  --pdb-cache tests/pdb_types
render-verification stderr: empty

cc -std=c11 -Wall -Wextra -Werror -fsyntax-only record_value-after.c
completed successfully

uv run python tools/dectest.py @smoke
4 scoped lanes of 838; no scoped regressions
```

The emitted function no longer declares or reads `local_8`:

```c
typedef struct Record Record;
int record_value(Record *arg0) {
    return (unsigned int)(((unsigned long)((unsigned int)(*(int *)(((long)arg0 + 0x4)))) + *(int *)(((long)arg0 + 0x8))));
}
```

A broader 85-test definedness/render/emission slice remains red with 12
failures and two expected failures. Rebuilding and rerunning that exact slice
from unmodified `ceefd4ca` produced the same 12 failures with the same cases
and diagnostics. They are current-master defects, not regressions introduced
by this increment. No baseline was changed.

The fail-closed def-use census passed four of six checks. Its new-finding and
improvement ratchets failed on broad current-tip drift: 21 functions have new
or shifted findings while all six C/Rust lane totals improve substantially
(for example clang O0 `140 -> 76` and rustc O0 `7898 -> 6524`). The PDB fixture
is outside that census. No baseline was refreshed, and these corpus movements
are not attributed to this narrow rule.
