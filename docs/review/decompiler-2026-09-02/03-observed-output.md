# 03. Observed output

Six fixture functions decompiled by hand on 2026-09-02 with the shipped
extension (`tools/build_guard.py` reported `fresh`), using

```
uv run glaurung decompile tests/decompiler_fixtures/build/<obj> --func <name> --style decbench --no-color
```

`--style decbench` is the scored style and the only fair one to read;
`--style c` is the low-level view and still prints flag registers and
`rsp = (rsp - 8)`. All six functions are rows in
`tests/open_defects/known_failures.json`.

## 3.1 `sc_mixed`, clang -O0 (structure axis, 2 gotos)

Source (`tests/decompiler_fixtures/src/01_conditional_polarity.c:90`):

```c
int sc_mixed(int a, int b, int c) {
    if ((a > 0 && b > 0) || c > 0)
        return 9;
    return 90;
}
```

Output:

```c
int sc_mixed(int arg0, int arg1, int arg2) {
    if ((0 < (long)(arg0))) {
        if ((0 < (long)(arg1))) {
            goto L_13bb;
        }
    }
    if (((long)(arg2) <= 0)) {
        goto L_13c7;
    }
    L_13bb: ;
    // x86-64 epilogue: restore rbp
    return 9;
    L_13c7: ;
    // x86-64 epilogue: restore rbp
    return 90;
}
```

What it shows. A three-term short-circuit at -O0 is a chain of conditional
blocks sharing two targets, which is a condition DAG, not a diamond. The region
algebra has no shape for it; `Region::Goto` is emitted to each shared join, and
the AST-level `guard_chain` passes do not recognise this instance. A
reaching-condition structurer (the DREAM approach) produces the source form
directly. DWARF names (`a`, `b`, `c`) are present in the object and not applied.

The same function at gcc -O2 renders as

```c
int sc_mixed(int arg0, int arg1, int arg2) {
    long ret;
    if ((((long)(arg0) <= 0) || ((long)(arg1) <= 0))) {
        ret = 90;
        if (((long)(arg2) <= 0)) {
            return ret;
        }
    }
    return 9;
}
```

which is correct and goto-free but inverted relative to the source and
carrying a `long ret` temporary that the source does not have.

## 3.2 `dowhile_atleastonce`, gcc -O2 (structure axis, 2 gotos)

Source (`03_loop_shapes.c:110`):

```c
int dowhile_atleastonce(const int *p) {
    int i = 0;
    int s = 0;
    do {
        s += p[i];
        i++;
    } while (i < N && p[i - 1] > 0);
    return s * 10 + i;
}
```

Output:

```c
int dowhile_atleastonce(const int * arg0) {
    int i;
    int s;
    long var0;
    long var4;
    long var6;
    long var7;
    long var8;
    var0 = (unsigned long)((unsigned int)(*(int *)(((long)arg0))));
    i = 1;
    var4 = (unsigned long)((unsigned int)(var0));
    goto L_1204;
    L_1200: ;
    i = (i + 1);
    var4 = var6;
    var0 = var7;
    L_1204: ;
    var8 = (unsigned long)((unsigned int)(i));
    var6 = var4;
    if (((long)((int)(var0)) <= 0)) {
        return (unsigned int)((var8 + ((unsigned long)((unsigned int)((var6 + (var6 * 4)))) * 2)));
    }
    var7 = (unsigned long)((unsigned int)(*(int *)(((long)arg0 + i * 4))));
    var6 = (unsigned long)((unsigned int)((var4 + var7)));
    if ((i != 7)) {
        goto L_1200;
    }
    var8 = 8;
    return (unsigned int)((8 + ((unsigned long)((unsigned int)((var6 + (var6 * 4)))) * 2)));
}
```

What it shows. gcc peeled the first iteration and rotated the loop; the loop
now has two exits (the `<= 0` test and the `i != 7` latch), one of which is a
return. `Region::While` carries one `exit`, so one of the pre-build proofs
fires and the whole function is emitted as a labelled CFG. `s * 10` has been
rendered as `(s + s*4) * 2` with no strength-reduction idiom recovery, and the
two return statements are copies of one expression. This is the most common
optimised loop shape in real code.

## 3.3 `loop_return_on_neg`, clang -O2 (structure axis, 7 gotos)

Source (`03_loop_shapes.c:222`):

```c
int loop_return_on_neg(const int *p) {
    int s = 0;
    for (int i = 0; i < N; i++) {
        s += p[i];
        if (s < 0)
            return i * 100 + (s & 0xFF);
    }
    return s;
}
```

Output (first 40 lines of about 90):

```c
int loop_return_on_neg(const int * arg0) {
    int s;
    int i;
    long ret;
    long var0;
    int var10;
    ...
    var0 = (unsigned long)((unsigned int)(*(int *)(((long)arg0))));
    if (((long)((int)(var0)) < 0)) {
        var2 = 0;
        s = var0;
        L_173c: ;
        return (unsigned int)(((unsigned int)((unsigned char)((s & 255))) + var2));
    }
    var7 = (var0 + *(int *)(((long)arg0 + 0x4)));
    s = (unsigned long)((unsigned int)(var7));
    if (((long)((int)(var7)) < 0)) {
        var2 = 100;
        goto L_173c;
    } else {
        var8 = (s + *(int *)(((long)arg0 + 0x8)));
        s = (unsigned long)((unsigned int)(var8));
        if (((long)((int)(var8)) < 0)) {
            var2 = 200;
            goto L_173c;
        } else {
            ...
```

What it shows. clang fully unrolled the loop (N = 8) and shares one return
block between eight early exits. The output nests eight `else` levels and
gotos into a label placed inside the first `if`. Two cheap post-structuring
cleanups would fix this without touching the CFG walk: duplicate a small
terminal block at each of its goto sites (tail duplication), and flatten
`else` after a `return`. Neither exists.

## 3.4 `duff_copy`, clang -O0 (unrecovered axis)

Source (`102_duffs_device.c:10`): a bounds-checked Duff's device over
`count % 8`.

Output (abridged):

```c
int32_t duff_copy(const int32_t * arg0, int32_t * arg1, int32_t arg2) {
    int index;
    int blocks;
    ...
    index = 0;
    if ((arg0 != 0)) {
        if ((arg1 != 0)) {
            if ((1 <= (long)(arg2))) {
                if ((((unsigned long)((unsigned int)(arg2)) == 16) | ((long)(arg2) < 16))) {
                    goto L_114c;
                }
            }
        }
    }
    local_4 = -1;
    // x86-64 epilogue: restore rbp
    return (unsigned int)(local_4);
    L_114c: ;
    var2 = ((unsigned int)(arg2) + 7);
    blocks = ((int)((((long)((int)(var2)) < 0) ? (unsigned long)((unsigned int)(((unsigned long)((unsigned int)(arg2)) + 14))) : (unsigned long)((unsigned int)(var2)))) >> 3);
    var19 = (unsigned long)((unsigned int)(((unsigned long)((unsigned int)(arg2)) - (unsigned long)((unsigned int)(((((long)(arg2) < 0) ? ... ) & -8))))));
    local_30 = (unsigned int)(var19);
    if (((((unsigned long)((unsigned long)((unsigned int)(var19))) < (unsigned long)(7)) | ((unsigned long)((unsigned int)((var19 - 7))) == 0)) == 0)) {
        goto L_12ad;
    }
    /* unrecovered indirect jump through ((long)((int)(*(int *)((0x2000 + (local_30 * 4))))) + 0x2000) */
    L_12ad: ;
    local_4 = index;
    // x86-64 epilogue: restore rbp
    return (unsigned int)(local_4);
}
```

What it shows. Four things at once:

- The DWARF parameter types (`const int32_t *`) and local names (`index`,
  `blocks`) are applied, but the parameter names are not (`arg0`, `arg1`,
  `arg2`).
- `(count + 7) / 8` and `count % 8` (signed division and modulo by a power of
  two) render as the compiler's sign-fixup ternaries. There is no idiom layer.
- The PIC-relative jump table (`*(int*)(0x2000 + i*4) + 0x2000`) is not
  resolved even at -O0 with an explicit range check, so the entire switch body
  is missing behind an "unrecovered indirect jump" comment.
- The range check `count < 1 || count > 16` has become
  `(1 <= count) && (count == 16 | count < 16)`.

## 3.5 `duff_copy`, gcc -O2 (unrecovered axis, plus a semantic hole)

Output (abridged):

```c
int32_t duff_copy(const int32_t * arg0, int32_t * arg1, int32_t arg2) {
    ...
    if ((arg0 == 0)) {
        goto L_12e0;
    }
    if ((arg1 == 0)) {
        goto L_12e0;
    }
    if (((unsigned long)(15) < (unsigned long)((unsigned long)((unsigned int)((arg2 - 1)))))) {
        goto L_12e0;
    }
    var1 = (long)arg0;
    var4 = (unsigned long)((unsigned int)((arg2 & 7)));
    /* unrecovered indirect jump through ((long)((int)((((unsigned long)((unsigned int)(var4)) == 0) ? 0xfffff2e8 : (((unsigned long)((unsigned int)(var4)) == 1) ? 0xfffff230 : ... *(int *)((0x2000 + ((unsigned long)((unsigned int)(var4)) * 4))))))))))))) + 0x2000) */
    L_1180: ;
    var21 = (long)((int)(var4));
    var4 = (unsigned long)((unsigned int)((var4 + 8)));
    ...
    *(int *)(((long)arg1 + var24)) = *(int *)((var1 + var24));
    ... (eight copies)
    if (0) {
        goto L_1180;
    }
    // x86-64 epilogue: tear down frame
    return (unsigned int)(var4);
    L_12e0: ;
    return 0xffffffff;
}
```

What it shows.

- The jump table index is `arg2 & 7` with no comparison guarding it; the
  compiler knew the range from the mask. The resolver wants a compare, so the
  table is unresolved, even though the readonly-data folder has already
  enumerated all eight table entries inline in the comment.
- **`if (0) { goto L_1180; }` is a wrong answer, not an ugly one.** The
  `do { ... } while (--blocks > 0)` latch condition has folded to a constant
  false, so the loop runs once. This function is already an `unrecovered`
  row, so the semantic hole is hidden behind the readability marker; it
  deserves its own strict xfail.
- `return -1` renders as `return 0xffffffff` in an `int32_t` function.
  Literal spelling ignores the destination type.
- The range check `count < 1 || count > 16` is the compiler's
  `(unsigned)(count - 1) > 15` and is rendered as such.

## 3.6 `tail_dispatch`, gcc -O2 (types and returns axes)

Source (`08_indirect_dispatch.c:69`):

```c
int tail_dispatch(int tag, int a, int b) {
    if (tag < 0 || tag >= 5)
        return -1;
    return ops[tag](a, b);
}
```

Output:

```c
long tail_dispatch(unsigned int arg0, unsigned int arg1, int arg2) {
    extern void h_add(void);
    ...
    static void (*ops[5])(void) = { (void (*)(void))h_add, ... };
    long ret;
    long var0;
    long var1;
    long var2;
    var0 = (long)((int)(arg0));
    var1 = (unsigned long)(arg1);
    var2 = (unsigned long)((unsigned int)(arg2));
    if (((unsigned long)(arg0) <= (unsigned long)(4))) {
        ret = ((long (*)(long, long))(ops[var0]))(var1, var2);
        return ret;
    }
    return 0xffffffff;
}
```

What it shows.

- The function-pointer table is recovered and named, and the tail call through
  it is rendered as an indirect call, which is correct and better than
  several competitors.
- `tag` is typed `unsigned int` because the compiler implemented
  `tag < 0 || tag >= 5` as an unsigned compare against 4. An unsigned
  range-check idiom is not evidence that the operand is unsigned; the type
  recovery treats it as such because unsigned is sticky in the join.
- The return type is `long` because the tail-called callee's return is
  unknown and the recovery widens to register width.
- The object carries DWARF that states `int tail_dispatch(int, int, int)`
  exactly. The declared prototype was not rendered. `decbench_render.rs:186`
  gates the declared prototype on the recovered arity and void-ness; both
  agree here, so the reason it was dropped was not chased in this review and
  should be.
- `-1` again renders as `0xffffffff`.

## What the six have in common

| defect | 3.1 | 3.2 | 3.3 | 3.4 | 3.5 | 3.6 |
|---|---|---|---|---|---|---|
| goto from a shape the region algebra lacks | x | x | x | x | x | |
| whole-function fallback | | x | | | | |
| shared return block not duplicated | x | x | x | x | | |
| unresolved jump table | | | | x | x | |
| signed div/mod idiom missing | | | | x | | |
| strength-reduction idiom missing | | x | | | | |
| range-check idiom missing | | | | x | x | x |
| literal ignores destination signedness | | | | | x | x |
| DWARF names or prototype not applied | x | x | x | x | x | x |
| unsigned inferred from an unsigned compare | | | | | | x |
| semantic hole (`if (0)` latch) | | | | | x | |
