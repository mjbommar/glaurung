# Executable LLIR — The Phase 0 Hardening Spec

> The load-bearing phase. Today's LLIR (`src/ir/types.rs`) is a *lossy
> static-analysis* IR. This spec turns it into a *total, precisely-typed,
> executable* one **without breaking** the existing decompiler/dataflow consumers.

## Current state (verified against `src/ir/types.rs`, 2026-06)

```rust
pub enum Value { Reg(VReg), Const(i64), Addr(u64) }      // ← no width
pub struct MemOp { base, index, scale, disp, size: u8, segment }  // ← no endian
pub enum BinOp { Add, Sub, Mul, Div, And, Or, Xor, Shl, Shr, Sar } // ← no width on the Op
pub enum Op { Assign, CondAssign, Bin, Un, Cmp, Load, Store, Jump,
              CondJump, Call, Return, Nop, Unknown { mnemonic } }   // ← Unknown is a hole
pub enum Flag { Z, C, Ule, S, Slt, Sle, O, P, A }        // ← GOOD: condition codes, keep
```

What's already right: **flags are condition-codes**, not raw EFLAGS bits (cross-
arch parity); three-address form is fine; `va` provenance per op is useful.

## Target shape

Introduce explicit **bit width** everywhere, **explicit width-change ops**, a
**footprint-declaring intrinsic** to replace `Unknown`, and **endianness** on
memory. Strawman (names to be finalized in implementation):

```rust
/// Bit width of a value (1, 8, 16, 32, 64, 128, 256, 512). Use a newtype so the
/// type system catches width-mismatch bugs.
pub struct Width(pub u16);

pub enum Value {
    Reg(VReg, Width),
    Const { value: u128, width: Width },   // store raw bits; sign is an op property, not the value's
    Addr(u64),                              // pointer-width by context
}

pub struct MemOp {
    pub base: Option<VReg>, pub index: Option<VReg>, pub scale: u8, pub disp: i64,
    pub size: u8,                           // access width in bytes (authoritative)
    pub endian: Endian,                     // NEW
    pub segment: Option<String>,
}

pub enum Op {
    Assign  { dst: VReg, src: Value, width: Width },
    Bin     { dst: VReg, op: BinOp, lhs: Value, rhs: Value, width: Width },   // modular at `width`
    Un      { dst: VReg, op: UnOp,  src: Value, width: Width },
    Cmp     { dst: VReg, op: CmpOp, lhs: Value, rhs: Value, width: Width },   // dst is 1-bit
    // NEW explicit width-change ops (P-code INT_ZEXT/INT_SEXT/SUBPIECE/PIECE; BIL UNSIGNED/SIGNED/HIGH/LOW)
    ZExt    { dst: VReg, src: Value, from: Width, to: Width },
    SExt    { dst: VReg, src: Value, from: Width, to: Width },
    Trunc   { dst: VReg, src: Value, from: Width, to: Width },
    Extract { dst: VReg, src: Value, hi: u16, lo: u16 },   // bit slice
    Concat  { dst: VReg, hi: Value, lo: Value },
    Ite     { dst: VReg, cond: VReg, t: Value, e: Value, width: Width }, // CMOV/SETcc, merge-friendly
    Load    { dst: VReg, addr: MemOp },
    Store   { addr: MemOp, src: Value },
    Jump    { target: u64 },
    CondJump{ cond: VReg, target: u64, inverted: bool },
    Call    { target: CallTarget },
    Return,
    Nop,
    /// Replaces Unknown. A typed, side-effect-declaring opaque op (VEX dirty call
    /// / P-code CALLOTHER / LLIL intrinsic). Refinable into real ops later.
    Intrinsic {
        name: String,                 // "cpuid", "pshufb", "rdtsc", "fadd", "syscall", …
        ins:  Vec<Value>,
        outs: Vec<(VReg, Width)>,
        reads_mem: bool,
        writes_mem: bool,
    },
}
```

### Flags as explicit predicate ops + producer/consumer

Keep `Flag` VRegs. Define each via an explicit predicate so a symbolic backend
gets an ordinary bit-vector (no VEX `cc_op` blowup):

- `Z`   ← `Cmp { Eq, result, 0 }`
- `C`   ← unsigned-carry predicate (P-code `INT_CARRY`)
- `S`   ← sign-bit `Extract` of the result
- `O`   ← signed-overflow predicate (`INT_SCARRY`/`INT_SBORROW`)
- `Slt`,`Sle`,`Ule` ← composed predicates as documented today

**Producer/consumer:** only materialize a flag's computation when a consumer reads
it. Extend the existing dead-flag DCE (`src/ir/dce.rs`) to enforce this.

### Sub-register writes — lifter responsibility, not IR magic

The machine's register file is a **flat byte array** (see
[`machine-state.md`](machine-state.md)). The x86-64 rule "32-bit write zero-extends
to 64, 8/16-bit write does not" is encoded by the **lifter**: a 32-bit dst write
emits the write *plus* a `ZExt 32→64` of the parent. The IR has no implicit rule.

## Migration strategy — don't break existing consumers

The decompiler, SSA, dataflow, and `ioctl_taint` all consume today's LLIR. Options
(decided in [ADR-0002](../05-decisions/adr-0002-executable-ir-vs-new-tier.md)):

**Chosen: evolve in place, behind a compatibility shim.**
1. Add width fields with `#[derive(Default)]`-style sensible defaults so existing
   construction sites compile, then mechanically fill real widths in the lifters.
2. Add the new ops additively; keep `Unknown` as a deprecated alias that lowers to
   `Intrinsic { name: mnemonic, ins: [], outs: [], reads_mem: true, writes_mem: true }`
   (maximally conservative footprint) during a transition window.
3. Land an **IR verifier** (`src/ir/verify.rs`) that asserts: every op's operand
   widths agree; every `VReg` read is defined or a function input; no `Unknown`
   remains after lifting (only `Intrinsic`). Run it in tests over all `samples/`.
4. Update consumers incrementally; the verifier + existing test suite is the
   safety net.

## Width inference at lift time

The lifters already know operand sizes from `iced-x86`/`capstone` operand info
(register class, memory access size, immediate size). Phase 0 threads that size
into the new width fields — it is *recovering* information the decoder already has
but the IR currently discards.

## Exit criteria

- `src/ir/types.rs` carries width on every value/op; `endian` on `MemOp`;
  `Op::Intrinsic` exists; explicit ext/trunc/extract/concat/ite ops exist.
- `lift_x86` emits widths + intrinsics + explicit zero-extend on 32-bit writes; no
  `Unknown` emitted (only `Intrinsic`).
- `src/ir/verify.rs` passes on every `samples/`/`tests/fixtures/` binary.
- The **entire existing test suite still passes** (decompiler, SSA, dataflow,
  ioctl_taint) — possibly after mechanical updates.

## References
- [`../01-research/ir-design-lessons.md`](../01-research/ir-design-lessons.md)
- [`../05-decisions/adr-0002-executable-ir-vs-new-tier.md`](../05-decisions/adr-0002-executable-ir-vs-new-tier.md)
