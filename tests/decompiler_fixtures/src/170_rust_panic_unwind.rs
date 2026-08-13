// 170_rust_panic_unwind.rs
//
// Rust panic and unwind machinery.
//
// A Rust panic is not an error return: it is a call to a `!`-returning function
// (`core::panicking::panic`, `panic_fmt`, `panic_bounds_check`, ...) that takes
// a static `&core::panic::Location` — file/line/column — and then unwinds. What
// that produces in the binary is the shape this fixture is about:
//
//   * a COLD basic block per panic site, usually relocated to the end of the
//     function or into `.text.unlikely`, carrying a relocation to a static
//     `Location` and a static string;
//   * a `noreturn` call, so the block has no successor and the CFG has a sink
//     that is NOT the function's return;
//   * `.gcc_except_table` / `.eh_frame` LSDA entries describing the unwind, and
//     — because these functions are `extern "C"` — an ABORT-ON-UNWIND shim that
//     Rust inserts at the FFI boundary, since a panic must never cross it.
//
// Every panic path below is REACHABLE IN THE CFG and UNREACHABLE FROM THE
// WRAPPER: the wrapper's guard makes the panicking predicate false for every
// input the harness can pass, so the fixture is safe to execute in-process while
// still containing the shapes. That separation is the entire point of this
// fixture: a decompiler must keep the cold block, must not fold it into the hot
// path, and must not conclude the hot path is unreachable.
//
// Exposure: every driver is `#[no_mangle] pub extern "C" fn` over plain i32/u32
// scalars and a caller-owned `*const i32` buffer. Guards are checked BEFORE the
// panicking callee is entered, indices are masked, and all arithmetic is
// `wrapping_*` (rustc enables overflow checks whenever opt-level is 0, so a
// plain `+` would be an additional, unguarded panic site).
//
// Deterministic: no allocation, no time, no address observation.
//
// One implementation note. A guard that DOMINATES the call is provable, and at
// -O LLVM's interprocedural range propagation duly deletes every panic block in
// this file — `#[inline(never)]` does not stop it, because these helpers are
// internal and all their call sites are visible. That would leave the optimized
// lane with nothing to recover. So each already-validated argument is passed
// through `core::hint::black_box`, which is the IDENTITY at runtime (the guard
// still holds, so the panic still cannot fire) but opaque to the optimizer (so
// the cold block survives). Verified: every helper below still contains its
// panic call at both -C opt-level=0 and -O.

use core::hint::black_box;

/// Panics on a zero divisor. Callable only through a wrapper that has already
/// rejected zero.
#[inline(never)]
fn strict_div(a: i32, b: i32) -> i32 {
    if b == 0 {
        panic!("strict_div: zero divisor");
    }
    // `wrapping_div` is total for every nonzero `b`, including i32::MIN / -1.
    a.wrapping_div(b)
}

/// The guard: `b == 0` returns before `strict_div` is entered, so the panic
/// block inside `strict_div` is never executed.
#[no_mangle]
pub extern "C" fn rust_panic_guarded_div(a: i32, b: i32) -> i32 {
    if b == 0 {
        return -1;
    }
    strict_div(a, black_box(b))
}

/// `assert!` — the message is a static string and the failure edge is a cold
/// `panic` call.
#[inline(never)]
fn require_small(n: u32) -> u32 {
    assert!(n <= 16, "require_small: out of range");
    n.wrapping_mul(3).wrapping_add(1)
}

/// The mask makes the assertion vacuously true for every u32.
#[no_mangle]
pub extern "C" fn rust_panic_assert(n: u32) -> u32 {
    require_small(black_box(n & 15))
}

/// `Option::unwrap` — panics through `core::panicking::panic` with the
/// "called `Option::unwrap()` on a `None` value" static message.
#[inline(never)]
fn table_lookup(i: usize) -> i32 {
    const TABLE: [i32; 8] = [3, -7, 11, 0, 41, -2, 19, 5];
    *TABLE.get(i).unwrap()
}

/// `i & 7` is always a valid index into an 8-element table, so `unwrap` never
/// sees `None`.
#[no_mangle]
pub extern "C" fn rust_panic_unwrap(i: u32) -> i32 {
    table_lookup(black_box((i & 7) as usize))
}

/// `Result::expect` — a second, distinct panic entry point (`expect_failed`),
/// with the error value formatted into the message.
#[inline(never)]
fn decode(v: i32) -> Result<i32, i32> {
    if v < 0 { Err(v) } else { Ok(v.wrapping_mul(2).wrapping_add(1)) }
}

#[inline(never)]
fn decode_or_die(v: i32) -> i32 {
    decode(v).expect("decode_or_die: negative input")
}

/// Masking to 15 bits keeps the value non-negative, so `expect` never fails.
#[no_mangle]
pub extern "C" fn rust_panic_expect(v: i32) -> i32 {
    decode_or_die(black_box(v & 0x7fff))
}

/// An explicit slice index whose panic is `panic_bounds_check` — a THIRD entry
/// point, with a different signature (index and length, no message string).
#[inline(never)]
fn strict_index(s: &[i32], i: usize) -> i32 {
    s[i]
}

/// `p` is null-checked and the index is reduced modulo a proven-nonzero length.
#[no_mangle]
pub extern "C" fn rust_panic_bounds(p: *const i32, n: u32, i: u32) -> i32 {
    if p.is_null() {
        return -1;
    }
    let len = if n > 16 { 16 } else { n } as usize;
    if len == 0 {
        return -2;
    }
    // SAFETY: the caller owns at least 16 i32s at `p`; `len <= 16`.
    let s: &[i32] = unsafe { core::slice::from_raw_parts(p, len) };
    strict_index(s, black_box((i as usize) % s.len()))
}

/// `unreachable!()` — the panic that claims it cannot happen, and here really
/// cannot: `sel % 4` is provably in 0..=3 WITHIN this function, so LLVM deletes
/// the arm outright at -O while -C opt-level=0 keeps it. Deliberately left as
/// the NEGATIVE CONTROL for this fixture: a panic block that legitimately
/// disappears, against seven that legitimately must not.
#[inline(never)]
fn quadrant(sel: u32, x: i32) -> i32 {
    match sel % 4 {
        0 => x.wrapping_add(1),
        1 => x.wrapping_mul(2),
        2 => x.wrapping_sub(3),
        3 => x.wrapping_neg(),
        _ => unreachable!("quadrant: modulus violated"),
    }
}

#[no_mangle]
pub extern "C" fn rust_panic_unreachable(sel: u32, x: i32) -> i32 {
    quadrant(black_box(sel), x)
}

/// Opaque clamp feeding `rust_panic_caught`.
#[inline(never)]
fn clamp15(v: i32) -> i32 {
    v & 0x7fff
}

/// An UNWIND LANDING PAD that is never entered. `catch_unwind` installs the
/// personality-routine machinery and a `.gcc_except_table` entry; the closure's
/// panic edge is dynamically dead (the value is never negative) while the EH
/// tables and the cold block remain in the binary.
#[no_mangle]
pub extern "C" fn rust_panic_caught(v: i32) -> i32 {
    let guarded = black_box(clamp15(v)); // never negative -> the panic below never fires
    let r = std::panic::catch_unwind(|| {
        if guarded < 0 {
            panic!("rust_panic_caught: negative");
        }
        guarded.wrapping_mul(3).wrapping_add(17)
    });
    match r {
        Ok(x) => x,
        Err(_) => -999,
    }
}

/// Several guarded panic sites in ONE function, so the optimizer's choice of
/// where to place (and whether to merge) the cold blocks is exercised. Each
/// guard is checked before its panicking callee runs.
#[no_mangle]
pub extern "C" fn rust_panic_multi(a: i32, b: i32, sel: u32) -> i32 {
    let mut acc: i32 = 0;
    if b != 0 {
        acc = acc.wrapping_add(strict_div(a, black_box(b)));
    }
    acc = acc.wrapping_add(require_small(black_box((a as u32) & 15)) as i32);
    acc = acc.wrapping_add(table_lookup(black_box((sel & 7) as usize)));
    acc = acc.wrapping_add(decode_or_die(black_box(a & 0x7fff)));
    acc = acc.wrapping_add(quadrant(black_box(sel), b));
    acc
}
