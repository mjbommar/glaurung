// 171_rust_overflow.rs
//
// Rust integer overflow semantics. This is where Rust differs from C most
// sharply, and where the four explicit families differ from EACH OTHER:
//
//   * `wrapping_*`  — two's-complement wraparound. Defined for every input.
//                     Identical to what C's UNSIGNED arithmetic does, and to
//                     what C's SIGNED arithmetic happens to compile to while
//                     being undefined behaviour there.
//   * `checked_*`   — returns `Option`, so the overflow test is a materialised
//                     value. On x86-64 this is the flag-consuming form: `add` /
//                     `seto`, or `imul` / `jo`. `checked_div` additionally
//                     covers b == 0 AND i32::MIN / -1.
//   * `saturating_*`— clamps to the type's extrema. Emits a conditional move
//                     against INT_MIN/INT_MAX rather than a branch.
//   * `overflowing_*`— returns (value, bool): the wrapping result AND the flag,
//                     so both halves are live at once.
//
// A decompiler that renders all four as plain C `a + b` produces output that
// disagrees with the binary on exactly the extremal inputs the fixture harness
// sweeps. None of these operations can panic, at any optimization level — which
// matters because rustc turns overflow checks ON whenever opt-level is 0, so a
// bare `a + b` here would be a panic site in the unoptimized lane and a silent
// wraparound in the optimized one.
//
// Also covered: the bit-twiddling intrinsics that lower to single instructions
// (`rotate_left` -> rol, `leading_zeros` -> lzcnt/bsr, `count_ones` -> popcnt,
// `trailing_zeros` -> tzcnt/bsf) and the shift forms, where Rust's `<<` is a
// panic on an over-wide shift count while `wrapping_shl` masks the count — a
// distinction C does not have at all (there it is undefined behaviour).
//
// Exposure: every driver is `#[no_mangle] pub extern "C" fn` over plain i32/u32
// scalars and one caller-owned `*mut i32` buffer. Shift counts are masked,
// pointers are null-checked, and every arithmetic form is total. No input the
// harness can pass can panic.
//
// Deterministic: pure functions of the arguments.

// --- wrapping ---------------------------------------------------------------

#[no_mangle]
pub extern "C" fn rust_wrapping_add(a: i32, b: i32) -> i32 {
    a.wrapping_add(b)
}

#[no_mangle]
pub extern "C" fn rust_wrapping_sub(a: i32, b: i32) -> i32 {
    a.wrapping_sub(b)
}

#[no_mangle]
pub extern "C" fn rust_wrapping_mul(a: i32, b: i32) -> i32 {
    a.wrapping_mul(b)
}

/// `wrapping_neg` and `wrapping_abs` are the two cases where i32::MIN is its own
/// image — the exact input a naive `-a` / `abs(a)` rendering gets wrong.
#[no_mangle]
pub extern "C" fn rust_wrapping_neg_abs(a: i32) -> i32 {
    a.wrapping_neg().wrapping_add(a.wrapping_abs())
}

// --- checked ----------------------------------------------------------------

/// `None` is encoded as i32::MIN so the overflow verdict is observable in the
/// return value (the `Option` itself cannot cross the FFI boundary).
#[no_mangle]
pub extern "C" fn rust_checked_add(a: i32, b: i32) -> i32 {
    match a.checked_add(b) {
        Some(v) => v,
        None => i32::MIN,
    }
}

#[no_mangle]
pub extern "C" fn rust_checked_mul(a: i32, b: i32) -> i32 {
    a.checked_mul(b).unwrap_or(i32::MIN)
}

/// `checked_div` is `None` for BOTH b == 0 and i32::MIN / -1; C has undefined
/// behaviour for both and typically traps.
#[no_mangle]
pub extern "C" fn rust_checked_div(a: i32, b: i32) -> i32 {
    a.checked_div(b).unwrap_or(-1)
}

/// The same for the remainder, whose i32::MIN % -1 case is the one most often
/// lost in lowering.
#[no_mangle]
pub extern "C" fn rust_checked_rem(a: i32, b: i32) -> i32 {
    a.checked_rem(b).unwrap_or(-2)
}

// --- saturating -------------------------------------------------------------

#[no_mangle]
pub extern "C" fn rust_saturating_add(a: i32, b: i32) -> i32 {
    a.saturating_add(b)
}

#[no_mangle]
pub extern "C" fn rust_saturating_sub(a: i32, b: i32) -> i32 {
    a.saturating_sub(b)
}

#[no_mangle]
pub extern "C" fn rust_saturating_mul(a: i32, b: i32) -> i32 {
    a.saturating_mul(b)
}

// --- overflowing ------------------------------------------------------------

/// Both halves of the `(value, overflowed)` pair are used, so the flag cannot be
/// dropped: on overflow the value is complemented.
#[no_mangle]
pub extern "C" fn rust_overflowing_mul(a: i32, b: i32) -> i32 {
    let (v, o) = a.overflowing_mul(b);
    if o { !v } else { v }
}

#[no_mangle]
pub extern "C" fn rust_overflowing_add(a: i32, b: i32) -> i32 {
    let (v, o) = a.overflowing_add(b);
    v.wrapping_add(if o { 1 } else { 0 })
}

// --- unsigned ---------------------------------------------------------------

/// Unsigned wrapping subtraction underflows to a huge value; `checked_sub`
/// reports it; `saturating_sub` clamps to 0. All three on one input.
#[no_mangle]
pub extern "C" fn rust_u32_sub_family(a: u32, b: u32) -> u32 {
    let w = a.wrapping_sub(b);
    let c = a.checked_sub(b).unwrap_or(0xDEAD_BEEF);
    let s = a.saturating_sub(b);
    w ^ c.rotate_left(7) ^ s.wrapping_mul(3)
}

/// Single-instruction bit intrinsics. `leading_zeros(0)` is 32 (defined), which
/// is precisely where a naive `bsr` lowering is wrong.
#[no_mangle]
pub extern "C" fn rust_u32_bits(a: u32) -> u32 {
    a.count_ones()
        .wrapping_mul(1_000_000)
        .wrapping_add(a.leading_zeros().wrapping_mul(10_000))
        .wrapping_add(a.trailing_zeros().wrapping_mul(100))
        .wrapping_add(a.reverse_bits() & 0xff)
}

/// `rotate_left` is a true rotate (`rol`), not a shift pair; the count is taken
/// modulo 32 by the intrinsic itself, so no mask is needed for totality.
#[no_mangle]
pub extern "C" fn rust_u32_rotate(a: u32, s: u32) -> u32 {
    a.rotate_left(s) ^ a.rotate_right(s)
}

// --- shifts -----------------------------------------------------------------

/// `wrapping_shl` / `wrapping_shr` mask the count to the type width, so they are
/// total for every u32 count. The plain `>>` on the masked count is the
/// arithmetic (sign-propagating) form; the u32 cast makes the logical form
/// observable in the same result.
#[no_mangle]
pub extern "C" fn rust_shift_family(a: i32, s: u32) -> i32 {
    let m = s & 31;
    let arith = a >> m; // arithmetic shift right
    let logic = ((a as u32) >> m) as i32; // logical shift right
    let wshl = a.wrapping_shl(s); // count masked by the intrinsic
    let wshr = a.wrapping_shr(s);
    arith
        .wrapping_mul(3)
        .wrapping_add(logic)
        .wrapping_add(wshl)
        .wrapping_sub(wshr)
}

/// `checked_shl` returns `None` for a count >= the bit width — a case that has
/// no C spelling at all.
#[no_mangle]
pub extern "C" fn rust_checked_shift(a: i32, s: u32) -> i32 {
    let l = a.checked_shl(s).unwrap_or(-1);
    let r = a.checked_shr(s).unwrap_or(-2);
    l.wrapping_mul(31).wrapping_add(r)
}

// --- narrowing conversions --------------------------------------------------

/// `as` casts are always truncating/wrapping in Rust (never UB), including the
/// signed/unsigned reinterpretations that C leaves implementation-defined
/// before C23.
#[no_mangle]
pub extern "C" fn rust_cast_chain(a: i32) -> i32 {
    let b = a as i8 as i32; // truncate then sign-extend
    let c = a as u8 as i32; // truncate then zero-extend
    let d = a as i16 as i32;
    let e = (a as u32) as i32; // bit-identical reinterpretation
    b.wrapping_mul(1000)
        .wrapping_add(c.wrapping_mul(100))
        .wrapping_add(d.wrapping_mul(10))
        .wrapping_add(e & 1)
}

// --- all four families, side by side, into a caller buffer ------------------

/// Writes the wrapping / checked / saturating / overflowing result of the same
/// operation into consecutive slots, so a single vector at an extremum makes
/// every family's answer differ. Requires an 8-element buffer; `out` is
/// null-checked and the writes are a fixed count that fits the harness's
/// 16-element allocation.
#[no_mangle]
pub extern "C" fn rust_overflow_matrix(out: *mut i32, a: i32, b: i32) -> i32 {
    if out.is_null() {
        return -1;
    }
    // SAFETY: the caller owns at least 16 i32s at `out`; exactly 8 are written.
    let dst: &mut [i32] = unsafe { core::slice::from_raw_parts_mut(out, 8) };
    dst[0] = a.wrapping_add(b);
    dst[1] = a.checked_add(b).unwrap_or(i32::MIN);
    dst[2] = a.saturating_add(b);
    dst[3] = {
        let (v, o) = a.overflowing_add(b);
        if o { !v } else { v }
    };
    dst[4] = a.wrapping_mul(b);
    dst[5] = a.checked_mul(b).unwrap_or(i32::MIN);
    dst[6] = a.saturating_mul(b);
    dst[7] = {
        let (v, o) = a.overflowing_mul(b);
        if o { !v } else { v }
    };
    dst.iter()
        .fold(0i32, |acc, v| acc.wrapping_mul(7).wrapping_add(*v))
}
