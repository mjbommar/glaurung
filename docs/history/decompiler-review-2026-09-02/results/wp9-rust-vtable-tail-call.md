# WP9 Rust vtable tail-call evidence

Date: 2026-09-03

## Defect

At O2, `167_rust_trait_objects:rustc:O2:rust_dyn_apply` ends with a machine
`jmp *%rcx`. The immediately preceding sequence calls the internal `choose`
function, loads `%rcx` from the returned trait object's vtable method slot
`[%rdx+0x18]`, moves the data pointer and argument into the ordinary SysV
argument registers, restores the frame, and jumps. The decompiler preserved
that as an `unrecovered indirect jump` even after the two-register result was
proven.

## Proof and change

`call_args::recover_proven_vtable_tail_calls` converts only the complete
evidence chain:

1. the indirect register jump is the final statement in its structured body;
2. that target register's last definition is a pointer-sized load from the
   active ABI's high INTEGER-result register;
3. the displacement is pointer-aligned and at least three words, beyond Rust's
   drop/size/alignment vtable metadata;
4. the nearest preceding resolved call has a recovered prototype whose integer
   width is exactly the ABI's two-word result width; and
5. nothing overwrites the high result register between that call and the slot
   load.

Only then does the existing argument reconstruction treat the transfer as an
indirect tail call. A bare computed jump, an unaligned slot, a scalar-returning
callee, or an overwritten high result stays explicit and unrecovered.

The rule is expressed through `machine_word_bytes`,
`wide_integer_return_width`, and `wide_integer_return_part`; it does not encode
`rax`/`rdx` as the general algorithm. On Win64 the prerequisite wide-pair
prototype cannot be produced by the preceding inference, so this path remains
fail-closed.

## TDD and fixture evidence

```text
cargo test --features python-ext --lib call_args::tail_calls::tests -- --nocapture
9 passed; 0 failed

uv run python tools/dectest.py \
  167_rust_trait_objects:rustc:O0 \
  167_rust_trait_objects:rustc:O2 --full
SCOPED: 2 lanes of 838 - no regressions in scope
```

After a fresh release rebuild, O2 now emits the same real virtual dispatch that
O0 already emitted:

```c
return ((long (*)(long, long))(*(long *)
    (((unsigned long)(((unsigned __int128)(var1) >> 64)) + 24)))
    (var1, (unsigned long)((unsigned int)(var0)));
```

The fixture still has its pre-existing `fail` verdict because the recovered C
uses machine-width `long` for the Rust `i32` return and retains extra transport
casts. The control-flow defect itself is closed: the output no longer omits the
terminal call or silently ends without a return.

## Broad-gate status

The required full Python gate was started against a fresh release build of the
concurrent worktree. Before interruption in the strict fixture compiler it had
completed 1,142 tests with 47 failures, 6 skips, 5 expected failures, and 14
deselections. The failures span analyst overlays, configuration invariants,
ARM32 semantics, control flow, def-use census, and emission invariants; this is
not a green repository gate and is not attributed to this isolated tail-call
increment.
