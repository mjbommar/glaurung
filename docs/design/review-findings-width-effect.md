# Review findings: bit-width & side-effect semantics through AST lowering

Verification of code-review recommendation #2 ("P0 — Preserve bit-width &
side-effect semantics through AST lowering") against the current code on branch
`master` (read-only investigation; no source changed).

All four sub-claims were checked against the actual lowering in
`src/ir/ast.rs`, the role-renaming in `src/ir/naming.rs`, the dead-store
elimination in `src/ir/dead_stores.rs`, the `Op` definitions in
`src/ir/types.rs`, and the emitting lifters (`src/ir/lift_x86.rs`,
`lift_arm64.rs`, `lift_arm32.rs`).

| Claim | Verdict | Current blast radius |
|-------|---------|----------------------|
| (a) ZExt/SExt/Trunc → plain assignment | **CONFIRMED** | Large (movzx/movsx/movsxd, index sign-extension) |
| (b) Concat → `hi \| lo` without shift | **CONFIRMED (latent)** | Zero — no lifter emits `Op::Concat` today |
| (c) Intrinsic loses inputs/outputs/effects | **CONFIRMED** | Real — `mul`/`imul`/`div` and ARM intrinsics |
| (d) edi/rdi collapse → DSE drops zero-extending write | **CONFIRMED** | Large (sub-register writes to arg/ret slots) |

---

## (a) ZExt, SExt, and Trunc all become plain assignments — CONFIRMED

`src/ir/ast.rs:319-326`:

```rust
// Width changes render as a plain assignment of the source — the cast is
// implicit in the higher-level form (`dst = src`).
Op::ZExt { dst, src, .. } | Op::SExt { dst, src, .. } | Op::Trunc { dst, src, .. } => {
    vec![Stmt::Assign {
        dst: dst.clone(),
        src: lower_value(src),
    }]
}
```

The three ops are matched together and their `from`/`to` `Width` fields
(defined at `src/ir/types.rs:244-265`) are discarded with `..`. All three lower
to identical `dst = src`. The rendered C therefore does **not** reflect
zero-extension, sign-extension, or truncation. There is no compensating cast
downstream: no `expr_reconstruct` cast pass exists, and every renderer
(`render`, `render_c`, `render_decbench`/`render_decbench_typed`) consumes the
already-collapsed AST, so the distinction cannot be recovered after lowering.

**Why it is a real correctness bug (not just imprecision):** ZExt and SExt
collapse to the *same* statement, so signed vs. unsigned widening is lost. The
lifter deliberately distinguishes them — see `lift_x86.rs:777-790`, whose own
comment records that emitting a plain Assign for all three "silently
zero-extended `movsx` — caught by the Unicorn differential oracle." Lowering
re-introduces exactly that defect one layer up.

### Concrete example

```asm
movsx  eax, byte ptr [rdi]     ; load signed char, sign-extend into eax/rax
```

Lifts to `Op::Load { tmp } ; Op::SExt { dst: eax, src: tmp, from:8, to:32 }`
(`lift_x86.rs:800-815`). Current rendered C:

```c
eax = *(u8)rdi;      // sign-extension gone; a 0xFF byte reads as 255, not -1
```

Correct rendering:

```c
eax = (int)(signed char)*rdi;   // or (int32_t)(int8_t)...
```

For an array index the same defect flips negative indices:
`movsxd rax, eax` on a negative `eax` must sign-extend; lowered as `rax = eax`
it reads as a huge positive offset.

### Fix approach

Add an `Expr::Cast { kind: ZExt | SExt | Trunc, from: Width, to: Width, src:
Box<Expr> }` node (or a width-carrying `Expr::Widen`/`Expr::Trunc`). Lower each
op to `Assign { dst, src: Expr::Cast { .. } }`. Renderers emit
`(uintN_t)`/`(intN_t)` casts; the DecBench renderer already has typed casting
machinery to reuse (`type_annotation`, `width_ctype` at `ast.rs:937-944`).

---

## (b) Concat(hi, lo) becomes `hi | lo` without shifting — CONFIRMED (latent)

`src/ir/ast.rs:349-358`:

```rust
// Concatenation: render as `hi | lo` (the shift amount needs operand
// widths, refined when widths flow through values — Phase 0.7).
Op::Concat { dst, hi, lo } => vec![Stmt::Assign {
    dst: dst.clone(),
    src: Expr::Bin {
        op: BinOp::Or,
        lhs: Box::new(lower_value(hi)),
        rhs: Box::new(lower_value(lo)),
    },
}],
```

`Op::Concat`'s own doc (`types.rs:274`) specifies `dst = (hi << width(lo)) |
lo`. The lowering drops the `<< width(lo)` shift, so `hi` and `lo` are OR'd
in place — wrong whenever `hi` has any set bits that should occupy the upper
half. The comment concedes the shift is missing (blocked on width tracking).

**Blast radius is currently zero.** No lifter constructs `Op::Concat`
(`grep 'Op::Concat' src/ir/lift_*.rs` is empty). The only producers/consumers
are the execution interpreter (`src/exec/interp.rs:278`, which implements the
shift *correctly*), `value_number.rs`, `use_def.rs`, `ioctl_taint.rs`, and the
Python bindings — none in the decompiler render path. So the bug is real in the
code but unreachable from rendered corpus output today. It becomes live the
moment a lifter emits `PIECE`/`ExprCompose` (e.g. 128-bit mul result modelling).

### Fix approach

`Op::Concat` carries no width for `lo`, so a correct fix needs that width. Add a
`lo_width: Width` field to `Op::Concat` (or thread widths through `Value`), then
lower to `(hi << lo_width_bits) | lo`. Low priority given zero current impact;
fix opportunistically alongside (a)'s width-carrying infrastructure.

---

## (c) Opaque intrinsics lose their inputs, outputs, and memory effects — CONFIRMED

`src/ir/ast.rs:378-382`:

```rust
Op::Intrinsic { name, ins, .. } => match semantic_comment_for_unknown(name) {
    Some(comment) => vec![Stmt::Comment(comment.to_string())],
    None if ins.is_empty() => vec![Stmt::Unknown(name.clone())],
    None => vec![Stmt::Unknown(format!("{}(...)", name))],
},
```

`Op::Intrinsic` (`types.rs:297-308`) carries `ins: Vec<Value>`,
`outs: Vec<(VReg, Width)>`, `reads_mem: bool`, `writes_mem: bool`. The match
binds only `name` and `ins`, discarding `outs`, `reads_mem`, `writes_mem`
entirely, and does **not** propagate the `ins` operands — the non-empty case
emits a literal `"name(...)"` string with an ellipsis, so even the inputs are
erased from the text. Critically, the `outs` writes vanish: the destination
registers are never assigned in the AST.

This path is reached in practice. `lift_x86.rs` emits `Op::Intrinsic` with real
operands for `mul` (`:905-911`, `ins:[rax, src]`, `outs:[rax, rdx]`), and for
`imul`/`div` (`:976`, `:1382`); `lift_arm64.rs` has 7 sites and `lift_arm32.rs`
1. So multiply/divide — common in a C corpus — render as opaque, and any
downstream read of `rax`/`rdx` after a `mul` reads a stale value: dataflow is
broken, not merely imprecise.

### Concrete example

```asm
mul rsi          ; rdx:rax = rax * rsi
mov rdi, rax     ; use the product
```

Current rendered C:

```c
unknown(mul(...));   // inputs, outputs, and the rax/rdx writes all lost
arg0 = ret;          // reads a stale rax; the product never reached it
```

Correct rendering (preserving the output assignment and inputs):

```c
ret = mul(ret, arg1);   // rax = rax * rsi   (rdx high half also modelled)
arg0 = ret;
```

### Fix approach

Add a structured `Stmt::Intrinsic { name, args: Vec<Expr>, outs: Vec<VReg>,
reads_mem, writes_mem }` (or lower to an assignment form
`out0 = name(args...)` when there is a single output). Preserving the `outs`
register writes is what keeps DCE/dead-store/use-def sound; the renderer prints
`name(args)` with real operands. `reads_mem`/`writes_mem` should at minimum
block reordering/elimination across the call.

---

## (d) edi/rdi collapse to one role name → DSE deletes a zero-extending write — CONFIRMED

Two mechanisms combine, and the pipeline runs them in the order required for the
bug (`src/python_bindings/ir.rs:472` role naming, then `:481` dead-store
elimination; comment at `:477-480` explicitly sequences them this way).

**1. Role naming collapses a full register and its sub-registers to one name.**
`src/ir/naming.rs:41-69` (`arg_slot_tables`) lists every ABI slot with *all* its
width aliases in one entry, e.g. SysV slot 0 = `["rdi", "edi", "di", "dil"]`.
The role-map build at `naming.rs:96-104` maps every alias in a slot to the same
`argN` string. So `rdi`, `edi`, `di`, `dil` all become `arg0`. Return-value
aliases collapse identically at `naming.rs:33-39` / `:105-110` (`rax`,`eax`,
`ax`,`al` → `ret`). Width information is erased at this point.

**2. Dead-store elimination unconditionally drops `X = X`.**
`src/ir/dead_stores.rs:71-79`:

```rust
// Drop `%X = %X` self-assigns unconditionally — they have no
// side effect and appear after naming collapses two aliases onto
// the same role-name (e.g. `%edi` and `%rdi` both becoming `%arg0`).
if matches!(
    &body[i],
    Stmt::Assign { dst, src: Expr::Reg(r) } if dst == r
) {
    body.remove(i);
    continue;
}
```

The comment openly acknowledges the self-assign arises *from the naming
collapse* — and removes it regardless of whether the original op changed width.

**The trap:** a 32-bit write on x86-64 zero-extends its 64-bit parent (clearing
the upper 32 bits); a `movzx`/`movsx` into a same-family register likewise
rewrites bits the "self-assign" appears to leave untouched. Once the extension
op has been flattened to `parent = child` by bug (a), and both names collapse to
`arg0`, the result is `arg0 = arg0`, which DSE deletes — silently discarding the
extension.

### Concrete example

```asm
movzx  rdi, dil      ; zero-extend low byte into rdi (clears bits 8..63)
call   foo           ; foo reads the full 64-bit rdi (arg0)
```

Lifting (`lift_x86.rs:788-790`): `Op::ZExt { dst: rdi, src: dil, from:8, to:64 }`.

- After lowering (bug **a**, `ast.rs:319-326`): `Assign { dst: rdi, src: dil }`.
- After role naming (`naming.rs:96-104`): both `rdi` and `dil` → `arg0`, giving
  `Assign { dst: arg0, src: arg0 }`.
- After DSE (`dead_stores.rs:73-79`): the statement is removed.

Rendered C (wrong):

```c
foo(arg0);          // the zero-extension is gone; foo sees the un-masked rdi
```

Correct behaviour keeps the masking:

```c
arg0 = (unsigned long)(unsigned char)arg0;   // rdi = zext8(dil)
foo(arg0);
```

The same defect fires for the classic 32-bit truncation idiom `mov edi, edi`,
which lifts to a plain `Op::Assign { edi, edi }` (`lift_x86.rs:751-756` — the
plain `Mov` path models **no** parent zero-extension at all) → `arg0 = arg0`
→ deleted, losing the clear of `rdi`'s upper 32 bits.

### Fix approach

This is a compound bug; the durable fix is (a). Once ZExt/SExt/Trunc carry an
`Expr::Cast`, the statement is `arg0 = (u64)(u8)arg0`, not `arg0 = arg0`, so the
DSE self-assign matcher no longer matches and the write survives. Two defensive
layers to add alongside:

- **DSE guard:** in `dead_stores.rs:73-79`, only drop `X = X` when the RHS is a
  bare `Expr::Reg` *with no width change* — i.e. never drop an assignment whose
  source is a cast/extension expression. (Requires (a) to make the cast
  visible.)
- **Naming refinement (optional):** keep width-distinct role names
  (`arg0` vs `arg0d`/`arg0b`) so a sub-register write is not textually identical
  to a parent read. Heavier; only needed if (a) is deferred.

---

## Blast radius & DecBench regression risk

- **(a) ZExt/SExt/Trunc** — affects a large share of functions: byte/short
  loads, boolean/char returns, and 32→64 index sign-extension are pervasive.
  Fixing adds casts that should *improve* type/GED/recompile fidelity, but any
  metric rewarding terse output may show text/byte-diff churn. Medium regression
  risk; gate behind fixture tests and re-baseline.
- **(b) Concat** — zero current blast radius (no emitter); no regression risk.
  Fix is cleanup/future-proofing only.
- **(c) Intrinsic** — affects every function containing `mul`/`imul`/`div` (and
  ARM intrinsics). Restoring the output assignment is a correctness gain with
  low regression risk: it turns `unknown(mul(...))` into a real dataflow edge
  that Joern/GED and recompilation need.
- **(d) edi/rdi + DSE** — affects functions with sub-register writes to
  argument/return slots (very common at all opt levels). Impact is tied to (a);
  the standalone DSE guard is low-risk.

### Recommended fix order

1. **(a)** — root cause; add the width-carrying `Expr::Cast` node. Unblocks (d).
2. **(c)** — structured `Stmt::Intrinsic` preserving `outs`/effects; independent,
   high correctness value, low risk.
3. **(d)** — DSE self-assign guard (and optional naming refinement) on top of (a).
4. **(b)** — Concat shift; latent, do last (or when a lifter first emits it).
