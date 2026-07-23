//! Helper registry — total instruction coverage with a small interpreter core.
//!
//! Following QEMU's "small core + helpers" split, complex or
//! environment-dependent instructions lift to [`Op::Intrinsic`](crate::ir::types::Op::Intrinsic)
//! and are executed by a registered helper rather than bloating `step()`. An
//! intrinsic with no registered helper halts cleanly
//! ([`Halt::UnsupportedIntrinsic`](crate::exec::interp::Halt)) — never a silent
//! wrong result.
//!
//! Helpers are plain `fn` pointers (not closures) so they can be looked up and
//! then called with `&mut Machine` without aliasing the registry. They operate
//! on the canonical machine state (`regs`/`mem`/`dom`).
//!
//! Determinism (a house rule): `rdtsc`/`rdtscp` read a **virtual** monotonic
//! counter and `cpuid` returns a **fixed** feature set — never host time/CPU
//! state. See `docs/design/execution-engine/02-architecture/determinism.md`.

use std::collections::HashMap;

use crate::exec::domain::Domain;
use crate::exec::interp::{Halt, Machine};
use crate::ir::types::{BinOp, VReg, Value, Width};

/// A helper: executes one intrinsic against the machine, reading `ins` and
/// writing `outs` (and/or fixed architectural registers). Returns `Err(halt)` to
/// stop execution.
pub type HelperFn<D> =
    fn(&mut Machine<D>, ins: &[Value], outs: &[(VReg, Width)]) -> Result<(), Halt>;

/// A name → helper map. Construct the default x86-64 set with
/// [`HelperRegistry::default_x86_64`].
pub struct HelperRegistry<D: Domain> {
    map: HashMap<String, HelperFn<D>>,
}

impl<D: Domain> Default for HelperRegistry<D> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

// Helper fns are plain fn pointers (Copy), so the registry clones cheaply
// regardless of domain (used when forking states).
impl<D: Domain> Clone for HelperRegistry<D> {
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
        }
    }
}

impl<D: Domain> HelperRegistry<D> {
    /// An empty registry (every intrinsic halts).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Register (or replace) a helper for an intrinsic name.
    pub fn register(&mut self, name: impl Into<String>, helper: HelperFn<D>) {
        self.map.insert(name.into(), helper);
    }

    /// Look up a helper by intrinsic name.
    pub fn get(&self, name: &str) -> Option<HelperFn<D>> {
        self.map.get(name).copied()
    }

    /// The default x86-64 helper set: the fixed-effect / environment intrinsics
    /// that the current opaque lifting already produces (no operands needed).
    pub fn default_x86_64() -> Self {
        let mut r = Self::empty();
        r.register("rdtsc", helper_rdtsc::<D>);
        r.register("rdtscp", helper_rdtsc::<D>);
        r.register("cpuid", helper_cpuid::<D>);
        r.register("bswap", helper_bswap::<D>);
        r.register("mul", helper_mul::<D>);
        r.register("div", helper_div::<D>);
        r
    }

    /// The default AArch64 helper set. Empty for now — AArch64 environment
    /// intrinsics (`mrs`/`svc`/…) are added as the lifter emits richer
    /// intrinsics; unmodelled ones halt cleanly until then.
    pub fn default_aarch64() -> Self {
        Self::empty()
    }
}

/// `rdtsc`/`rdtscp`: edx:eax ← a virtual monotonic counter.
fn helper_rdtsc<D: Domain>(
    m: &mut Machine<D>,
    _ins: &[Value],
    _outs: &[(VReg, Width)],
) -> Result<(), Halt> {
    let tsc = m.next_tsc();
    let lo = m.dom.constant(Width::W32, (tsc & 0xffff_ffff) as u128);
    m.regs.write(&mut m.dom, &VReg::phys("eax"), lo);
    let hi = m.dom.constant(Width::W32, (tsc >> 32) as u128);
    m.regs.write(&mut m.dom, &VReg::phys("edx"), hi);
    Ok(())
}

/// `cpuid`: a fixed, deterministic feature set (independent of the leaf in eax).
/// A richer per-leaf model can replace this later; the point is determinism, not
/// fidelity to any real CPU.
fn helper_cpuid<D: Domain>(
    m: &mut Machine<D>,
    _ins: &[Value],
    _outs: &[(VReg, Width)],
) -> Result<(), Halt> {
    for (reg, val) in [
        ("eax", 0u128),
        ("ebx", 0x6c61_7572_676e_6168u128 & 0xffff_ffff), // arbitrary fixed bytes
        ("ecx", 0),
        ("edx", 0),
    ] {
        let v = m.dom.constant(Width::W32, val);
        m.regs.write(&mut m.dom, &VReg::phys(reg), v);
    }
    Ok(())
}

/// `bswap`: reverse the bytes of the operand. An operand-carrying helper —
/// reads `ins[0]` at the output width and byte-reverses it through the domain
/// (explicit widths, so it works for both concrete and symbolic backends).
fn helper_bswap<D: Domain>(
    m: &mut Machine<D>,
    ins: &[Value],
    outs: &[(VReg, Width)],
) -> Result<(), Halt> {
    let (dst, w) = (&outs[0].0, outs[0].1);
    let v = m.read(&ins[0], w);
    let nbytes = w.bytes();
    // Build the reversal: byte 0 (LSB of the source) becomes the MSB of the
    // result. acc accumulates [b0 .. b_{i}] with b0 at the top.
    let mut acc = m.dom.extract(&v, 8, 0);
    let mut acc_w = 8u16;
    for i in 1..nbytes {
        let bi = m.dom.extract(&v, (i + 1) * 8, i * 8);
        acc = m.dom.concat(&acc, &bi, Width(acc_w), Width::W8);
        acc_w += 8;
    }
    m.regs.write(&mut m.dom, dst, acc);
    Ok(())
}

/// `mul` (unsigned multiply): `outs[1]:outs[0] = ins[0] * ins[1]` at the operand
/// width. Two-output helper — the full 2w-bit product is split into low (rax/…)
/// and high (rdx/…) halves. Computed by widening both operands to `2w` and
/// extracting; works for concrete and symbolic backends.
fn helper_mul<D: Domain>(
    m: &mut Machine<D>,
    ins: &[Value],
    outs: &[(VReg, Width)],
) -> Result<(), Halt> {
    // Robustness (2026-06-17): a well-formed `mul` intrinsic carries 2 inputs and
    // 2 outputs (lo=rax/…, hi=rdx/…). A malformed / edge-case lift that yields an
    // empty `outs` must NOT panic-abort the entire driver's symbolic exploration
    // (the kdnic.sys `index out of bounds: len is 0 but index is 0` crash that
    // silently dropped coverage). Skip the degenerate op; model 1-output (low
    // product only, e.g. a 2/3-operand imul that routed here) and full 2-output.
    if ins.len() < 2 || outs.is_empty() {
        return Ok(());
    }
    let (lo_reg, w) = (&outs[0].0, outs[0].1);
    let w2 = Width(w.bits() * 2);
    let a = m.read(&ins[0], w);
    let b = m.read(&ins[1], w);
    let az = m.dom.zext(&a, w, w2);
    let bz = m.dom.zext(&b, w, w2);
    let prod = m.dom.binop(BinOp::Mul, &az, &bz, w2);
    let lo = m.dom.trunc(&prod, w);
    m.regs.write(&mut m.dom, lo_reg, lo);
    if outs.len() >= 2 {
        let hi_reg = &outs[1].0;
        let hi = m.dom.extract(&prod, w.bits() * 2, w.bits());
        m.regs.write(&mut m.dom, hi_reg, hi);
    }
    Ok(())
}

/// `div` (unsigned divide): the `2w`-bit dividend `ins[0]:ins[1]` (hi:lo, i.e.
/// rdx:rax) is divided by `ins[2]`; quotient → `outs[0]` (rax/…), remainder →
/// `outs[1]` (rdx/…). Computed at `2w` then truncated. (Division by zero is a
/// CPU fault; the domain returns 0 — callers should model the fault separately.
/// Signed `idiv` needs a signed-divide domain primitive and is not yet handled.)
fn helper_div<D: Domain>(
    m: &mut Machine<D>,
    ins: &[Value],
    outs: &[(VReg, Width)],
) -> Result<(), Halt> {
    let (q_reg, w) = (&outs[0].0, outs[0].1);
    let r_reg = &outs[1].0;
    let w2 = Width(w.bits() * 2);
    let hi = m.read(&ins[0], w);
    let lo = m.read(&ins[1], w);
    let divisor = m.read(&ins[2], w);
    let dividend = m.dom.concat(&hi, &lo, w, w);
    let div2 = m.dom.zext(&divisor, w, w2);
    let q = m.dom.binop(BinOp::Div, &dividend, &div2, w2);
    // remainder = dividend - q*divisor  (at 2w), then truncate.
    let prod = m.dom.binop(BinOp::Mul, &q, &div2, w2);
    let rem = m.dom.binop(BinOp::Sub, &dividend, &prod, w2);
    let qt = m.dom.trunc(&q, w);
    let rt = m.dom.trunc(&rem, w);
    m.regs.write(&mut m.dom, q_reg, qt);
    m.regs.write(&mut m.dom, r_reg, rt);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::concrete::Concrete;
    use crate::ir::types::Op;

    #[test]
    fn rdtsc_writes_counter_and_advances() {
        let mut m: Machine<Concrete> = Machine::new(Concrete);
        let intr = Op::opaque("rdtsc");
        m.step(&intr);
        let first = m.regs.read(&mut m.dom, &VReg::phys("eax"));
        m.step(&intr);
        let second = m.regs.read(&mut m.dom, &VReg::phys("eax"));
        assert_ne!(first, second, "virtual TSC must advance");
    }

    #[test]
    fn cpuid_is_deterministic() {
        let mut m1: Machine<Concrete> = Machine::new(Concrete);
        let mut m2: Machine<Concrete> = Machine::new(Concrete);
        m1.step(&Op::opaque("cpuid"));
        m2.step(&Op::opaque("cpuid"));
        for r in ["eax", "ebx", "ecx", "edx"] {
            assert_eq!(
                m1.regs.read(&mut m1.dom, &VReg::phys(r)),
                m2.regs.read(&mut m2.dom, &VReg::phys(r)),
            );
        }
    }

    #[test]
    fn unregistered_intrinsic_still_halts() {
        use crate::exec::interp::Flow;
        let mut m: Machine<Concrete> = Machine::new(Concrete);
        assert_eq!(
            m.step(&Op::opaque("vpbroadcastb")),
            Flow::Halt(Halt::UnsupportedIntrinsic("vpbroadcastb".into()))
        );
    }
}
