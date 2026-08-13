// 166_rust_generics.rs
//
// Rust monomorphized generics. A single generic function body is instantiated at
// three concrete integer widths (i8 / i16 / i32); the compiler emits three
// separate machine-code bodies with different truncation and sign-extension
// behaviour, and there is nothing in the binary that says they came from one
// source function. Recovering them means recovering three unrelated-looking
// functions that happen to share a shape.
//
// The interesting recovery signals:
//   * `<i8 as Acc>::step` truncates to 8 bits after every operation; the i16 and
//     i32 instantiations do not. Same source, three different width lattices.
//   * generic `pick`/`fold` monomorphise into bodies whose only difference is the
//     width of a compare and a move.
//   * at -O the instantiations are frequently inlined into the extern "C"
//     wrapper, so the wrapper's body is the ONLY evidence the generic existed.
//
// Exposure: every driver is `#[no_mangle] pub extern "C" fn` over plain i32/u32
// scalars and caller-owned `*const i32` / `*mut i32` buffers. Counts and indices
// are masked to <= 16 inside the wrapper, pointers are null-checked, and all
// arithmetic is `wrapping_*`, so no input the harness can pass can panic or run
// out of bounds. (rustc turns on overflow checks whenever opt-level is 0, so
// plain `+` would panic in the unoptimized lane on hostile fuzz values; the
// wrapping forms keep both lanes semantically identical.)
//
// Deterministic: no addresses, no allocation-order dependence, no time, no
// randomness.

#![allow(clippy::needless_range_loop)]

/// The generic bound. Every operation is width-preserving and wrapping, so an
/// instantiation is total over its whole domain.
trait Acc: Copy {
    /// Narrow an i32 into this accumulator's width.
    fn seed(v: i32) -> Self;
    /// One fold step; wraps at this type's width.
    fn step(self, k: i32) -> Self;
    /// Widen back to i32 (sign-extending).
    fn out(self) -> i32;
    /// Total order pick, at this type's width.
    fn pick_max(self, other: Self) -> Self;
}

impl Acc for i8 {
    fn seed(v: i32) -> Self {
        v as i8
    }
    fn step(self, k: i32) -> Self {
        // truncating multiply-accumulate: the i8 instantiation loses the high
        // bits that the i16/i32 ones keep.
        self.wrapping_mul(3).wrapping_add(k as i8)
    }
    fn out(self) -> i32 {
        self as i32
    }
    fn pick_max(self, other: Self) -> Self {
        if self >= other { self } else { other }
    }
}

impl Acc for i16 {
    fn seed(v: i32) -> Self {
        v as i16
    }
    fn step(self, k: i32) -> Self {
        self.wrapping_mul(3).wrapping_add(k as i16)
    }
    fn out(self) -> i32 {
        self as i32
    }
    fn pick_max(self, other: Self) -> Self {
        if self >= other { self } else { other }
    }
}

impl Acc for i32 {
    fn seed(v: i32) -> Self {
        v
    }
    fn step(self, k: i32) -> Self {
        self.wrapping_mul(3).wrapping_add(k)
    }
    fn out(self) -> i32 {
        self
    }
    fn pick_max(self, other: Self) -> Self {
        if self >= other { self } else { other }
    }
}

/// The one generic body. `#[inline(never)]` keeps a distinct symbol per
/// instantiation in the unoptimized lane; the optimized lane is free to inline
/// it anyway, which is exactly the contrast we want across lanes.
#[inline(never)]
fn fold_generic<T: Acc>(v: i32, n: u32) -> i32 {
    let mut acc = T::seed(v);
    let mut i: u32 = 0;
    while i < n {
        acc = acc.step(i as i32);
        i = i.wrapping_add(1);
    }
    acc.out()
}

/// A second generic body, over the same bound but a different shape (reduction
/// with a comparison instead of a chain of arithmetic).
#[inline(never)]
fn max_generic<T: Acc>(buf: &[i32]) -> i32 {
    let mut best = T::seed(if buf.is_empty() { 0 } else { buf[0] });
    for &x in buf {
        best = best.pick_max(T::seed(x));
    }
    best.out()
}

/// `n` is masked to 0..=15, so the loop is bounded for every possible input.
#[no_mangle]
pub extern "C" fn rust_generic_i8(v: i32, n: u32) -> i32 {
    fold_generic::<i8>(v, n & 15)
}

#[no_mangle]
pub extern "C" fn rust_generic_i16(v: i32, n: u32) -> i32 {
    fold_generic::<i16>(v, n & 15)
}

#[no_mangle]
pub extern "C" fn rust_generic_i32(v: i32, n: u32) -> i32 {
    fold_generic::<i32>(v, n & 15)
}

/// Runtime selection between the three instantiations. A decompiler that fuses
/// the three monomorphizations into one body gets this wrong for at least one
/// `sel`, because the widths differ.
#[no_mangle]
pub extern "C" fn rust_generic_dispatch(sel: u32, v: i32, n: u32) -> i32 {
    let n = n & 15;
    match sel % 3 {
        0 => fold_generic::<i8>(v, n),
        1 => fold_generic::<i16>(v, n),
        _ => fold_generic::<i32>(v, n),
    }
}

/// All three instantiations combined, so one call exercises every body.
#[no_mangle]
pub extern "C" fn rust_generic_mixed(v: i32, n: u32) -> i32 {
    let n = n & 15;
    let a = fold_generic::<i8>(v, n);
    let b = fold_generic::<i16>(v, n);
    let c = fold_generic::<i32>(v, n);
    a.wrapping_mul(1_000_003)
        .wrapping_add(b.wrapping_mul(7))
        .wrapping_add(c)
}

/// Generic reduction over a caller-owned buffer.
///
/// `p` is null-checked; `n` is clamped to at most 16 elements, which is the
/// harness's buffer allocation. `sel` picks the instantiation.
#[no_mangle]
pub extern "C" fn rust_generic_max(p: *const i32, n: u32, sel: u32) -> i32 {
    if p.is_null() {
        return -1;
    }
    let len = if n > 16 { 16 } else { n } as usize;
    // SAFETY: the caller owns at least 16 i32s at `p` (harness contract) and
    // `len <= 16`.
    let buf: &[i32] = unsafe { core::slice::from_raw_parts(p, len) };
    match sel % 3 {
        0 => max_generic::<i8>(buf),
        1 => max_generic::<i16>(buf),
        _ => max_generic::<i32>(buf),
    }
}

/// Generic write-back: each instantiation stores its own narrowed fold into the
/// caller's buffer, so the per-width truncation is observable as a buffer diff
/// and not only as a return value.
#[no_mangle]
pub extern "C" fn rust_generic_fill(out: *mut i32, n: u32, v: i32) -> i32 {
    if out.is_null() {
        return -1;
    }
    let len = if n > 16 { 16 } else { n } as usize;
    // SAFETY: caller owns >= 16 i32s at `out`; `len <= 16`.
    let dst: &mut [i32] = unsafe { core::slice::from_raw_parts_mut(out, len) };
    let mut sum: i32 = 0;
    for (i, slot) in dst.iter_mut().enumerate() {
        let k = (i & 15) as u32;
        let w = match i % 3 {
            0 => fold_generic::<i8>(v, k),
            1 => fold_generic::<i16>(v, k),
            _ => fold_generic::<i32>(v, k),
        };
        *slot = w;
        sum = sum.wrapping_add(w);
    }
    sum
}
