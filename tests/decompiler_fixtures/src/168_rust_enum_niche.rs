// 168_rust_enum_niche.rs
//
// Rust enum layout, including the niche optimizations that make a Rust enum
// unrecognisable as a tagged union.
//
// Three distinct layouts appear here:
//
//   * `Shape` — a data-carrying enum with variants of different sizes. Laid out
//     as an explicit discriminant plus a union-like payload area; the payload
//     offset is chosen by the compiler and is NOT stable across variants, so
//     reading `Pair.0` and `Tagged.id` may or may not be the same load.
//
//   * `Option<&i32>` — the NULL POINTER OPTIMIZATION. `size_of::<Option<&i32>>()
//     == size_of::<&i32>() == 8`. There is no discriminant at all: `None` IS the
//     null pointer. A `match` on it decompiles to a null test, which looks
//     exactly like a C null check and gives no hint that an enum existed.
//
//   * `Option<NonZeroU32>` — the same trick at 4 bytes, folded into a payload
//     that is documented never to be zero. `None` IS `0u32`.
//
//   * `Option<Option<NonZeroU32>>` — the niche is EXHAUSTED. `Option<NonZeroU32>`
//     already spends the only forbidden value (0) on its own `None`, so every
//     u32 bit pattern is now valid and the outer `Option` has to grow a real tag:
//     8 bytes, not 4. Verified at runtime by `rust_niche_sizes`. The lesson for a
//     decompiler is that niche folding is NOT compositional — the same source
//     shape one level deeper has a completely different layout.
//
// Exposure: every driver is `#[no_mangle] pub extern "C" fn` over plain i32/u32
// scalars and caller-owned `*const i32` / `*mut i32` buffers. Discriminant
// selectors are taken modulo the variant count, indices are masked to <= 15,
// pointers are null-checked (and the null case is a legitimate `None`), and all
// arithmetic is `wrapping_*`. No input the harness can pass can panic.
//
// Deterministic: `rust_niche_sizes` returns compile-time constants; nothing else
// observes an address.

use core::num::NonZeroU32;

/// A data-carrying enum: differing payload sizes force a real discriminant.
enum Shape {
    Unit,
    Pair(i32, i32),
    Tagged { id: i32, v: i32 },
    Wide(i64),
    Byte(i8),
}

/// Total over all inputs: `kind` is reduced modulo the variant count.
#[inline(never)]
fn make(kind: u32, a: i32, b: i32) -> Shape {
    match kind % 5 {
        0 => Shape::Unit,
        1 => Shape::Pair(a, b),
        2 => Shape::Tagged { id: a, v: b },
        3 => Shape::Wide((a as i64).wrapping_mul(0x1_0000_0001).wrapping_add(b as i64)),
        _ => Shape::Byte(a as i8),
    }
}

/// The discriminant read plus five payload decodings. Each arm produces a value
/// in its own decade, so a mis-recovered discriminant lands in the wrong decade
/// and the differential catches it.
#[inline(never)]
fn eval(s: &Shape) -> i32 {
    match s {
        Shape::Unit => 1,
        Shape::Pair(x, y) => 100i32.wrapping_add(x.wrapping_mul(3)).wrapping_add(*y),
        Shape::Tagged { id, v } => 200i32.wrapping_add(id.wrapping_sub(*v)),
        Shape::Wide(w) => 300i32.wrapping_add((*w as i32) ^ ((*w >> 32) as i32)),
        Shape::Byte(b) => 400i32.wrapping_add(*b as i32),
    }
}

#[no_mangle]
pub extern "C" fn rust_enum_eval(kind: u32, a: i32, b: i32) -> i32 {
    eval(&make(kind, a, b))
}

/// The enum crosses a function boundary BY VALUE, so its ABI layout (how many
/// registers, which halves carry the discriminant) is exercised rather than just
/// its in-memory form.
#[inline(never)]
fn combine(x: Shape, y: Shape) -> i32 {
    eval(&x).wrapping_mul(31).wrapping_add(eval(&y))
}

#[no_mangle]
pub extern "C" fn rust_enum_by_value(k1: u32, k2: u32, a: i32, b: i32) -> i32 {
    combine(make(k1, a, b), make(k2, b, a))
}

/// Only the discriminant, with no payload use: the compiler is free to emit a
/// bare tag load and a jump table.
#[no_mangle]
pub extern "C" fn rust_enum_discriminant(kind: u32, a: i32, b: i32) -> i32 {
    match make(kind, a, b) {
        Shape::Unit => 0,
        Shape::Pair(..) => 1,
        Shape::Tagged { .. } => 2,
        Shape::Wide(_) => 3,
        Shape::Byte(_) => 4,
    }
}

// --- niche optimization: Option<&T> is a nullable pointer ------------------

/// `Option<&i32>` built from a raw pointer. `as_ref()` performs the null test;
/// the resulting `Option` has NO tag — the pointer value IS the tag.
///
/// `p` may legitimately be null (the harness never passes null, but the code is
/// total either way); `idx` is masked to the 16-element buffer.
#[no_mangle]
pub extern "C" fn rust_option_ref(p: *const i32, idx: u32) -> i32 {
    let off = (idx & 15) as usize;
    // SAFETY: when non-null the caller owns at least 16 i32s at `p`, and
    // `off <= 15`. `as_ref` itself performs the null check.
    let opt: Option<&i32> = unsafe { p.add(off).as_ref() };
    match opt {
        Some(v) => v.wrapping_add(1000),
        None => -1,
    }
}

/// The same niche used as a RETURN value: the function returns one pointer-sized
/// register that is either a valid address or zero.
#[inline(never)]
fn first_positive(buf: &[i32]) -> Option<&i32> {
    for v in buf {
        if *v > 0 {
            return Some(v);
        }
    }
    None
}

#[no_mangle]
pub extern "C" fn rust_option_ref_find(p: *const i32, n: u32) -> i32 {
    if p.is_null() {
        return -2;
    }
    let len = if n > 16 { 16 } else { n } as usize;
    // SAFETY: caller owns >= 16 i32s at `p`; `len <= 16`.
    let buf: &[i32] = unsafe { core::slice::from_raw_parts(p, len) };
    match first_positive(buf) {
        Some(v) => *v,
        None => -1,
    }
}

// --- niche optimization: Option<NonZeroU32> is a u32 with 0 == None ---------

/// `NonZeroU32::new` is the niche construction: it is a compare against zero,
/// and the `Option` it returns is bit-identical to its argument.
#[no_mangle]
pub extern "C" fn rust_option_nonzero(v: u32) -> u32 {
    match NonZeroU32::new(v) {
        Some(nz) => nz.get().wrapping_mul(3) ^ 0x5a,
        None => 0xFFFF_FFFF,
    }
}

/// Nested `Option`s where the niche has run out: the outer layer carries an
/// explicit discriminant word beside the u32 payload (8 bytes total), so three
/// distinct results — outer `None`, inner `None`, and a payload — come from two
/// different mechanisms in one match.
#[no_mangle]
pub extern "C" fn rust_option_nested(v: u32, sel: u32) -> u32 {
    let inner: Option<NonZeroU32> = NonZeroU32::new(v);
    let outer: Option<Option<NonZeroU32>> = if sel & 1 == 0 { None } else { Some(inner) };
    match outer {
        None => 7,
        Some(None) => 8,
        Some(Some(nz)) => nz.get().wrapping_add(9),
    }
}

/// The niche flowing through a caller-owned buffer: each element is interpreted
/// as an `Option<NonZeroU32>` and rewritten, so both the `None` encoding and the
/// payload encoding are visible as memory.
#[no_mangle]
pub extern "C" fn rust_option_niche_fill(out: *mut i32, n: u32) -> i32 {
    if out.is_null() {
        return -1;
    }
    let len = if n > 16 { 16 } else { n } as usize;
    // SAFETY: caller owns >= 16 i32s at `out`; `len <= 16`.
    let dst: &mut [i32] = unsafe { core::slice::from_raw_parts_mut(out, len) };
    let mut count: i32 = 0;
    for slot in dst.iter_mut() {
        let o = NonZeroU32::new(*slot as u32);
        *slot = match o {
            Some(nz) => {
                count = count.wrapping_add(1);
                nz.get().wrapping_add(1) as i32
            }
            None => -5,
        };
    }
    count
}

/// The layout facts themselves, as compile-time constants: (Option<&i32>,
/// Option<NonZeroU32>, Option<u32>, Option<Option<NonZeroU32>>) sizes packed
/// into one i32. Observed value on x86-64: 8_04_08_08, i.e. 8 / 4 / 8 / 8 —
/// `Option<u32>` and `Option<Option<NonZeroU32>>` have no niche left and pay for
/// a tag, which is the contrast that proves the other two are niche-optimized.
#[no_mangle]
pub extern "C" fn rust_niche_sizes() -> i32 {
    let a = core::mem::size_of::<Option<&i32>>() as i32; // 8 (NPO)
    let b = core::mem::size_of::<Option<NonZeroU32>>() as i32; // 4 (niche)
    let c = core::mem::size_of::<Option<u32>>() as i32; // 8 (no niche)
    let d = core::mem::size_of::<Option<Option<NonZeroU32>>>() as i32; // 8 (niche exhausted)
    a.wrapping_mul(1_000_000)
        .wrapping_add(b.wrapping_mul(10_000))
        .wrapping_add(c.wrapping_mul(100))
        .wrapping_add(d)
}
