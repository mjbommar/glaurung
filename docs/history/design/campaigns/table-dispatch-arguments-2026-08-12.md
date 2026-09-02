# Why a table-dispatched call drops its arguments

> **Kind:** record · **Date:** 2026-08-12
> Resolved since: the defect described here now passes in `baseline.json`.

*Investigated 2026-08-12 while working item 4 ("symbolize code addresses used as
values"). The fix attempted here was measured, found to produce WRONG output,
and reverted. This records the root cause so the next attempt starts from it.*

*Item 4 itself was completed separately and by other means — see the closing
section — so this document is now only about the REMAINING half: an indirect
call through a function-pointer table still drops its arguments.*

## The defect

`95_function_pointer_table:gcc:O2:dispatch_operation` fails. The source is

```c
static BinaryOp const OPERATIONS[5] = {op_add, op_sub, op_and, op_xor, op_max};

int32_t dispatch_operation(int32_t which, int32_t a, int32_t b) {
    if (which < 0 || which >= 5) return -1;
    return OPERATIONS[which](a, b);
}
```

and the recovery is

```c
    ret = ((int (*)(void))(OPERATIONS[ret]))();
```

— the arguments are gone, while the signature still declares all three. The
machine code is

```
    movslq %edi,%rax
    mov    %esi,%edi          ; a -> first argument
    mov    %edx,%esi          ; b -> second argument
    cmp    $0x4,%eax
    ja     1170
    lea    0x2cf9(%rip),%rdx  ; OPERATIONS
    jmp    *(%rdx,%rax,8)
```

## Root cause: a chicken-and-egg between arity and liveness

Three facts combine:

1. The call target is a LOADED VALUE, so there is no callee name to look up a
   prototype under.
2. The arguments are PASS-THROUGH. At -O2 they are already in the registers
   this function received them in (modulo the two-instruction shuffle above),
   so the backward scan for argument setup has almost nothing to find.
3. Because the call is reconstructed with no arguments, **the shuffle that sets
   them up looks dead** — nothing reads `edi`/`esi` afterwards — and dead-store
   elimination removes it. The evidence needed to recover the arity is deleted
   by the consequence of not having recovered it.

That third step is why the rendered body does not even contain the shuffle.

## What was tried, and why it was reverted

The callee layouts map (`recover_direct_callee_layouts`) is keyed by VA and only
ever populated from DIRECT call targets, so it had nothing to say here. Two
changes made it apply:

* seed the callee set with the targets of any relocation-proven function-pointer
  table the caller references (a cheap syntactic scan for the table's address);
* let a call through such a table use the agreed layout of its entries, the way
  the ARM branch of `fold_one_call` already does for a locked callee layout.

That produced a call with the right arity and the right pointer type:

```c
    ret = ((int (*)(int, int))(OPERATIONS[ret]))(arg0, arg1);
```

and the WRONG arguments. The layout names architectural storage (`rdi`, `rsi`),
which the naming pass then renders as this function's own parameter roles
`arg0, arg1` — but the values in those registers at the call are the shuffled
ones, `a` and `b`, which are `arg1, arg2`. Plausible, well-typed, and wrong,
which is worse than visibly missing. Reverted.

## What a real fix needs

The layout must be known **before** dead-store elimination runs, so the shuffle
survives and ordinary argument folding can read the values out of it — rather
than being reintroduced afterwards as register NAMES that no longer denote the
values they held. Concretely, one of:

* recover function-pointer-table callee layouts in the same pass that recovers
  direct-callee layouts, and hand them to argument reconstruction before DCE; or
* teach dead-store elimination that a call through a proven table may read the
  ABI argument registers (an over-approximation of uses, which is the safe
  direction — see `abi::call_effects`), so the setup survives on its own.

The second is smaller and matches how the ABI's may-use set already protects
direct calls. It should be measured against the whole corpus, not just this
fixture: `abi::call_effects` was widened once on 2026-08-12 in a related attempt
and cost twelve regressions.


## Postscript: what item 4 needed, and why it is not this

The address-taken half of item 4 was fixed on the same day without touching any
of the above. It needed two things:

* `recover_direct_callee_layouts` seeded from ADDRESS OPERANDS as well as direct
  call targets, so a function that is referenced but never called (`main`,
  passed by address to `__libc_start_main`) acquires a recovered contract; and
* `write_expr_dec` rendering the identifier only when this render has SELECTED a
  prototype for it, which now comes from `ir::symbol_env` — one agreed record
  per callee, keyed by the identifier being printed.

That second condition is the whole difference from the attempt of 2026-08-05,
which emitted `extern void <name>(void);` and cost 656 -> 633 because the
declaration conflicted with the callee's real signature once the unit was
compiled. Measured this time: **zero regressions, and
`127_inline_linkage:{gcc,clang}:O0:inline_address_taken` fail -> pass.**

The table-dispatch problem above is untouched by that change, because its
failure is not a naming one: the arguments are eliminated before anything can
name them.
