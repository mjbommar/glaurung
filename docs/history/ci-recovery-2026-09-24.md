# CI recovery on master, 2026-09-23 to 2026-09-24

> **Kind:** record · **Date:** 2026-09-24

Every CI workflow on `master` had been red since at least 2026-09-20, and no
`CI` run in the previous hundred had passed. This records what was repaired,
what was measured, and what is still open, with the command behind each number.
It is a delivery record, not an all-green claim.

Work ran from `master` @ `c4c56e51`. Decompiler repairs were done by parallel
agents in isolated git worktrees and cherry-picked onto `master` after review.
No DecBench or Joern run was made, and nothing was posted upstream.

## Repaired

| Area | Commits | What was wrong |
|---|---|---|
| Python types and format | `0f45b614` | `uvx ty check python/` reported 412 diagnostics and `ruff format --check` 13 files; both are now clean. `[tool.ty]` gives ty the `sys.path` roots the tests import from. |
| Documentation gates | `ec87f1da`, `0dbc36d5`, `acd84b66` | 210 history records had no dated banner and 395 were missing from the index. There were dead links into code that moved to cindergraph, stale generated references, and a stale AArch64 disassembly contract. The tutorial fixture drifted with the Python version. |
| Build lanes | `67563b5d`, `0861dbc8` | A bench called a `#[cfg(test)]`-only function (all 13 feature lanes failed). The fuzz crate built `runtime_analysis` without `exec`. `llvm-strip` was never installed for `GLAURUNG_REQUIRE_TOOLCHAINS=1`. The wheel smoke build asked manylinux2014 for a `python3` older than `requires-python`. One example was unformatted. |
| Test tiers | `6db50c55`, `bf625b53`, `539d837a` | About 60 `python-core` failures came from tests that need LFS objects, the fixture build, Docker or a compiler. The facet generator missed pathlib joins, LFS data outside `samples/`, and a file's own marker. The ptrace single-step wait slept a flat 5 ms, which exhausted trace budgets on CI; it now backs off from 20 µs. |
| Ratchets | `f744e8ee`, `0bd4e66e`, `97d3d933`, `c67edcb6` | The census, fitness and large-module baselines had not been written since 2026-09-02. Each refresh carries its justification: the 583 tests lost are exactly the cindergraph extraction; 13 modules are marked SPLIT OWED with a named seam; `structure_v2/presentation.rs` was folded into `cleanup.rs` to keep WP4 under its nine-file cap. Ten dialect gaps were promoted after `a98f3af4` fixed them. |
| Tooling | `584c2eb5`, `5c57a6cc` | `build_guard` fingerprinted a stale `cpython-312` `.so` beside the live 3.14 one. The Rust-sysroot signature harvest read a stats key renamed on 09-03. |
| Discovery determinism | `ea9f4508` | The per-function 100 ms wall clock made default discovery truncate `win10-webservices.dll` on some runs and not others. `timeout_ms=0` now disables that clock; the default is unchanged (see Open). |
| Float/fixed-point O2 lanes | `8ce624e0` | Four causes, three bisected: `d4fe3568` (a 64-bit dividend narrowed to `int`), `6993a984` (a `double` return taken from `rax`), `20364f46` (a coalesced 64-bit loop state declared `int`). 21 matrix cells fixed. `tools/dectest.py --full @o0 @o2` compared against master: 824 lanes, 21 fail→pass, 0 pass→fail. |
| Stack canary (gcc 13, stripped) | `605dc338` | The guard slot inside a promoted frame object was rendered as the constant `0x28`. `test_build_configuration_invariants.py` passes under both gcc 13 and gcc 15 (116 passed, 12 skipped, 3 xfailed). |
| Runtime frames on glibc 2.39 | `3f1bd111` | `relate_one_write` needed exactly one "saved fp + address in `main`" pair on the stack; glibc 2.39's startup frame supplies a second. A return address now counts only if a `call` inside `main` precedes it. In an ubuntu:24.04 container: `test_runtime_sample_harness.py` 256 passed, 4 failed (was 56 more failures). |
| ABI, variadic, i386 | `6946c5c9` .. `20f08979` | Five of the agent's seven commits. `xchg` on a byte register now updates the full register (fixes `141_atomics` O0 on both compilers). i386 `ebp`/`esp` frame coordinates now join. `__stack_chk_fail_local` counts as protector evidence. An empty guard left by GCC's variadic `test %al,%al` is removed. Test spellings follow three bisected, deliberate renderer changes. |

Verification on the merged tree (`c67edcb6`), with `lld` and `llvm`
installed on this machine:

- `cargo test --features python-ext --lib`: 4574 passed, 0 failed.
- Static gates:
  - `uvx ruff format --check python/`, `uvx ruff check python/` and `uvx ty check python/` are clean.
  - `cargo fmt --all -- --check` and `tools/gen_native_stub.py --check` pass.
  - `gen_{cli,env,feature,pass}_reference.py --check` all pass.
- The whole Python suite result is in the addendum at the end.

CI evidence as of `5c57a6cc`: `CI` (wheel smoke) and `feature build gate`
passed, the first green runs in this history. `test suite` had `ruff and ty`
and `cargo test --features symbolic` green.

## Open, with evidence

**Two ABI commits held back after the def-use census regressed.** The ABI
branch's by-hand `test_decompiler_defuse_census.py` run, compared against
master, gave 3 cells with new undefined reads (`128:clang:O2:pointer_to_const_walks`,
`145:gcc:O2:flattened_gcd`, `168:rustc:O0:rust_option_niche_fill`) and 14
where master removes an undefined read the branch keeps (O2 loops such as
`25_kmp_search:gcc:O2`, `80_trie:gcc:O2`). The suspects were not separated:

- `7e2f6330`: do not fold a promoted value live out of its loop.
- `0ee6ca6d`: identity sidecar slots limited to the locked prototype.

Neither is on master. Both remain on `worktree-agent-aab85c51c891dc09b`.
Without them, `121_dense_expression:gcc:O0:dense_fold`,
`113_varargs:gcc:O2:variadic_none` and `07_packet_parser:clang:O0:parse_packet`
still fail, as they did before, along with three `test_variadic_abi_invariants`
ids and `test_clang_union_views_of_call_result_round_trip`. Next step: revert
one suspect at a time on that branch and re-run the census, then narrow the
loop fold to the case where the post-loop read would otherwise see a stale
value. The float commit's census, compared line by line against the same master
census log, removes one undefined read (`172_float_double_widths:gcc:O0:
narrow_after_double_math`) and adds none. The one differing line,
`151_wide_branch_ladder:clang:O0`, timed out on master, so there was nothing
to compare. The canary and runtime commits were not run through the census.

**Fixture baseline is stale in both directions.** An x86-64 `pytest -m slow`
matrix run on the ABI branch before merge (3 failed, 24 passed, 8 errors) found:

- **Improvements:** 49 cells that `tests/decompiler_fixtures/baseline.json`
  records as failing also pass on master. The baseline was last refreshed at
  `2411d01b` (2026-09-12).
- **Regressions:** 32 pass→fail cells reproduce on master as well.
- **Structural errors:** the 8 errors come from a panic in the
  `11_call_shapes:gcc:O2` lane: "const_fold::fold_constants reported no change
  but edited the body".

A single baseline refresh is owed once the regressions below are fixed or
knowingly accepted.

**Control-flow regressions, root causes found, not fixed:**

- `164_nested_tlv_walker:gcc:O2`: a self-recursive call passes 2 of 5
  arguments. `src/ir/call_args/fold_one_call.rs` stops at the first register
  argument not set up next to the call, and SysV has no fallback to the
  callee's known register list; ARM does. Pass or fail depends on leftover
  register values.
- `45_string_algorithms:clang:O2:format_decimal`: the `digits[12]` stack array
  is lost, so the recovered C reads an undefined `rsp`. Bisected to `af65c260`.
- `131`, `145`, `151`, `16_red_black_tree:rb_validate`: somewhere in
  `34d25589..11afa94a`, the "coalesced" value-numbering series, with about five
  bisect steps left. `rb_validate` is fixed by `8ce624e0`.

**Rust lanes, culprits bisected, fix not merged:**

- Culprits:
  - `4f6762bc`: GOT-resolved `std` bodies are pulled in with mismatched arity.
  - `079e26d5`: a dead-path `%rdx` read becomes `arg2`.
  - `8eec8cc2`: the coalesced `ret` is typed from its 32-bit definition.
- The unverified fix is on branch `wip/rust-lane-callee-arity-2026-09-24`.
  It fixed 2 of 6 cells before its last edits and was never run on the full
  matrix.
- These cells were already failing in CI's matrix on 2026-09-09.
- Regenerating the known-failure inventory gives 93 type and 58 return
  mismatches against ceilings of 82 and 41.

**Other open items:**

- `fold_returns` recognises only `rax#N` since `8f5285b9`. The fix is on
  branch `wip/return-folds-identity-2026-09-24`, verified by unit tests and,
  after the WIP commit was written, by a full `-m slow` matrix run that
  introduced no new pass→fail cell (built together with the two held-back
  commits, so its census effect is not separated). It is the fix for
  `test_o2_pointer_return_keeps_declared_dwarf_kind[clang]`.
- Variadic: five lanes remain strict-xfail because they read an `al` or
  save-area value that later code uses.
- `test_vectorized_mem_copy_round_trips_clang_o2`: the 16-byte copy through a
  bare `xmm0` in a `void` function is not rejoined into a memmove. The likely
  culprit, `58e45ccd`, is not bisected.
- Four runtime tests fail only on CI's compilers, because they assume a
  particular clang or gcc code shape:
  - `optimized_direct_store_absence` (2 cells);
  - `optimized_ioctl_trace[bad-3735928559]`;
  - `argv_byte_to_command_memory[pie-O2-gcc]`.

**Decisions for the maintainer:**

- **Discovery default:** `Budgets::timeout_ms` still defaults to 100 ms, so
  default discovery on a very large function depends on machine load. `0`
  would make it reproducible.
- **Size debt:** 14 modules carry SPLIT OWED entries in
  `test_large_module_review.py`. The largest is
  `runtime_analysis/instruction_trace.rs` at 7,397 lines.
- **Fixture tests CI never runs:** `decompiler-fixtures.yml` runs `-m fixtures`
  only on `test_known_decompiler_failures.py`. About 30 fixture-tier files run
  in no CI job. Widening it should wait until the fixture regressions above
  are closed.
- **Nightlies:** perf and fuzz nightlies have been red throughout and were not
  examined.

## Resume evidence

- **Worktree branches** (local, not pushed):
  - `worktree-agent-a4f2ebd8878e43499` (float)
  - `worktree-agent-aab85c51c891dc09b` (ABI)
  - `worktree-agent-a06954aaefc33b5f1` (runtime)
  - `worktree-agent-a6d8440ed6b49dbf2` (Rust lanes and canary)
  - `worktree-agent-add8131ad941c6d26` (control flow, no commits)
- **WIP branches pushed to origin:**
  - `wip/rust-lane-callee-arity-2026-09-24`
  - `wip/return-folds-identity-2026-09-24`
- **CI-parity container:** Dockerfile and scripts under
  `~/.cache/glaurung/tmp/ci2404/`. It is ubuntu:24.04 with gcc 13, clang 18 and
  glibc 2.39, run with `--cap-add SYS_PTRACE`.
- **Test side effect:** a full `pytest python/tests/` run rewrites
  `tests/test_census_baseline.json`. Check `git status` before committing
  after one.

## Addendum: whole Python suite

`uv run pytest python/tests/ -n 8 -p no:cacheprovider` on this debug build:

- **Before, on the first commit of this work (`0f45b614` tree):** 108 failed,
  8 errors, 4858 passed, 480 skipped, 696 xfailed.
- **After, on `c67edcb6`:** the run had not finished when this record was
  committed. It had sat at 95% for more than ten minutes on slow Rust-fixture
  decompiles. Its progress markers at that point were 4711 passed, 42 failed,
  4 errors, 314 skipped and 831 xfailed.

The remaining failures are the decompiler cells and lanes listed under Open.
These counts are from progress markers, not a terminal summary. Read the final
line of `~/.cache/glaurung/tmp/fullsuite-final.log` before relying on them.
