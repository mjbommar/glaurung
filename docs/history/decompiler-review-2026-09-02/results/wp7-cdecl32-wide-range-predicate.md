# WP7 cdecl32 wide range predicate — 2026-09-06

> **Kind:** record · **Date:** 2026-09-06

Behavior commit `f39bdf0e` and census commit `98ea766c` close one bounded
expression-readability defect exposed after cdecl32 wide-parameter recovery.
They do not recover the remaining i386 switch, make its execution cell pass,
or establish WP3's general stable-value identity.

## Defect

GCC compares a cdecl32 `uint64_t` against a word-sized limit with two dword
operations. After lossless lifting and parameter materialization, the real
fixture-215 O2 guard was still rendered as flag/borrow algebra:

```c
((0 < high) | ((0 - high) < (5 < low))) == 0
```

The compiler then repeats the same comparison inside the accepted arm. Once
the first predicate is understood, the output was effectively:

```c
if (op <= 5) {
    if (5 < op) return 30;
    /* indirect table dispatch */
}
```

The nested branch is unreachable under the exact outer path condition. Its
target remains a legitimate typed jump-table case; only that duplicate direct
edge is impossible.

## Accepted contracts

Comparison fusion now recognizes the exact 32-bit borrow identity

```text
(0 <u hi) | ((0 - hi) <u (limit <u lo)) == wide >u limit
```

only when all of the following are proved:

- `hi` is exactly the unsigned 32-bit projection `wide >> 32`;
- `lo` is exactly the unsigned 32-bit view of the same value;
- the source value has recovered unsigned eight-byte type;
- the limit is a non-negative 32-bit constant; and
- any intervening aliases have one definition and depend only on registers
  that are never assigned anywhere in the function.

The proof environment is block-local and ephemeral. It does not parse display
names, export a second value identity, or claim that mutable physical/register
roles are SSA values. Signed sources, mismatched halves, wrong widths,
multiply-defined aliases, aliases of later-mutated sources, effectful
expressions, and unresolved definitions all decline.

After ordinary boolean normalization, a guard-chain pass removes a leading
nested `if` only when its comparison is the structural, cast-preserving exact
inverse of the outer comparison. Both predicates must be free of calls and
memory reads, the inner guard must have no `else`, and only comments may
precede it. A width mismatch, memory read, or intervening statement declines.

## Real output and limits

The first half of i386 O2 `wide_selector_mixed` now renders:

```c
if ((unsigned long)(op) <= (unsigned long)(5)) {
    /* unrecovered indirect jump through ... */
}
```

The flag/borrow tree and impossible nested branch are gone. The indirect jump
is deliberately still present: production switch discovery/structuring occurs
before this late typed AST cleanup, so the fixture remains execution-red. The
next WP5 increment must transport the proved wide range relation to the typed
CFG boundary rather than rerun structuring from rendered text.

The signed selector is also still red. Its high word belongs to the distinct
wide value `op + 3`, formed by `add`/`adc`; recovering that relation requires a
separate proved wide-arithmetic composition and is not inferred by this rule.

## Verification

- Nineteen comparison-fusion tests cover the accepted identity and its width,
  signedness, half-origin, definition-count, and mutable-dependency refusals.
- Seventeen guard-chain tests cover exact contradiction removal plus width,
  memory, and intervening-work refusals.
- The release-built real i386 O2 readability ratchet requires the recovered
  `op <= 5`, rejects the inverse nested guard, and rejects the exposed
  `0 - high` borrow spelling.
- All 20 host fixture-215 function cells remain execution-correct. The complete
  host sweep executes 824 of 838 lanes with zero regressions and reproduces 35
  pre-existing unratcheted improvements.
- The final complete 410-lane i386 sweep reproduces the pre-increment result:
  the same four historical regressions and 25 stale improvements, with no
  execution-verdict movement attributable to this readability slice.
- The remaining fixture-215 architecture slice reproduces its previously
  documented two A32 O0 regressions and one x86-64-GCC15 O2 improvement; none
  is new movement from this increment.
- The generated census at `98ea766c` records 4,649 declared tests, an IR
  subtotal of 2,129, and zero never executed. The six-test census suite and the
  new real-binary ratchet pass together.
- The required exact-clean-checkout `cargo test --features python-ext` gate at
  `98ea766c` exits zero: its library target reports 4,132 passed, zero failed,
  and five ignored; every integration and documentation target also passes.
  The longest identity-retrieval target reports 44 passed, zero failed, and
  ten ignored in 589.44 seconds while sharing CPU with the host corpus sweep.
