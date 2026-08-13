// 169_rust_slices_bounds.rs
//
// Rust slices and bounds checks.
//
// A Rust slice is a FAT POINTER (data, len) — two registers, no length stored in
// memory beside the data. Every `s[i]` therefore compiles to `cmp len, i; jae
// .panic` followed by the load, and the panic target is a cold block that calls
// `core::panicking::panic_bounds_check` and never returns. That cold block is
// the single most common thing a decompiler mis-structures: it is reachable in
// the CFG, it is `noreturn`, and it must NOT be folded into the hot path.
//
// This fixture puts three indexing styles side by side so the difference in
// emitted code is the whole point:
//   * `s[i]` — the bounds check and its cold panic block are emitted, and the
//     index is reduced modulo the length so the panic can never fire;
//   * `s.get(i)` — no panic path at all; the check becomes an `Option` and the
//     "failure" is an ordinary value;
//   * iterator forms (`iter`, `windows`, `chunks`, `zip`, `rev`, `enumerate`) —
//     the check is HOISTED OUT of the loop entirely, so the loop body has no
//     compare at all and the loop bound is the only surviving evidence.
//
// The two lanes disagree on purpose, and that disagreement is the fixture's
// second axis. At `-C opt-level=0` every check and every panic block is present
// (verified: `rust_slice_index`, `_index_pair`, `_get`, `_windows`, `_split_zip`
// all carry panic calls). At `-O` LLVM proves `i % len < len` and DELETES the
// check outright, so the same source function has a bounds check in one lane and
// none in the other. A decompiler must be right about both, and must not report
// a check the optimized binary does not contain.
//
// Exposure: every driver is `#[no_mangle] pub extern "C" fn` over plain i32/u32
// scalars and caller-owned `*const i32` / `*mut i32` buffers. Pointers are
// null-checked, lengths are clamped to the harness's 16-element buffer, indices
// are reduced modulo a proven-nonzero length, and all arithmetic is `wrapping_*`.
// No input the harness can pass can panic or read out of bounds.
//
// Deterministic: reads and writes only the caller's buffer; no address escapes.

/// Clamp a caller-supplied count to the buffer the harness guarantees.
#[inline(always)]
fn clamp_len(n: u32) -> usize {
    if n > 16 { 16 } else { n as usize }
}

/// Direct indexing. The bounds check is emitted and its panic block is present
/// in the binary; `idx % len` makes it unreachable for every input, and the
/// empty case returns before the index ever happens.
#[no_mangle]
pub extern "C" fn rust_slice_index(p: *const i32, n: u32, i: u32) -> i32 {
    if p.is_null() {
        return -1;
    }
    let len = clamp_len(n);
    if len == 0 {
        return -2;
    }
    // SAFETY: caller owns >= 16 i32s at `p`; `len <= 16`.
    let s: &[i32] = unsafe { core::slice::from_raw_parts(p, len) };
    let idx = (i as usize) % s.len(); // provably < s.len()
    s[idx] // <-- bounds check + cold panic block, never taken
}

/// Two dependent indexes, so the compiler emits two checks and may or may not
/// merge them.
#[no_mangle]
pub extern "C" fn rust_slice_index_pair(p: *const i32, n: u32, i: u32) -> i32 {
    if p.is_null() {
        return -1;
    }
    let len = clamp_len(n);
    if len == 0 {
        return -2;
    }
    // SAFETY: as above.
    let s: &[i32] = unsafe { core::slice::from_raw_parts(p, len) };
    let a = (i as usize) % s.len();
    let b = (a + 1) % s.len();
    s[a].wrapping_mul(3).wrapping_add(s[b])
}

/// `get()` — the checked form with NO panic path. `i` is deliberately NOT
/// clamped: out-of-range is a legitimate input here and yields `None`.
#[no_mangle]
pub extern "C" fn rust_slice_get(p: *const i32, n: u32, i: u32) -> i32 {
    if p.is_null() {
        return -1;
    }
    let len = clamp_len(n);
    // SAFETY: caller owns >= 16 i32s at `p`; `len <= 16`.
    let s: &[i32] = unsafe { core::slice::from_raw_parts(p, len) };
    match s.get(i as usize) {
        Some(v) => v.wrapping_add(7),
        None => -7,
    }
}

/// `get()` on a sub-range: `get(a..b)` is `None` for an inverted or overlong
/// range, again without a panic path. Both endpoints are unclamped on purpose.
#[no_mangle]
pub extern "C" fn rust_slice_get_range(p: *const i32, n: u32, a: u32, b: u32) -> i32 {
    if p.is_null() {
        return -1;
    }
    let len = clamp_len(n);
    // SAFETY: as above.
    let s: &[i32] = unsafe { core::slice::from_raw_parts(p, len) };
    match s.get((a as usize)..(b as usize)) {
        Some(sub) => sub.iter().fold(0i32, |acc, v| acc.wrapping_add(*v)),
        None => -9,
    }
}

/// Plain iterator: the bounds check is hoisted out and the loop body is a bare
/// load-and-add.
#[no_mangle]
pub extern "C" fn rust_slice_iter_sum(p: *const i32, n: u32) -> i32 {
    if p.is_null() {
        return -1;
    }
    let len = clamp_len(n);
    // SAFETY: as above.
    let s: &[i32] = unsafe { core::slice::from_raw_parts(p, len) };
    s.iter().fold(0i32, |acc, v| acc.wrapping_add(*v))
}

/// `enumerate` + `rev`: the index is synthesised by the iterator rather than
/// used to address, so no check survives at all.
#[no_mangle]
pub extern "C" fn rust_slice_rev_enumerate(p: *const i32, n: u32) -> i32 {
    if p.is_null() {
        return -1;
    }
    let len = clamp_len(n);
    // SAFETY: as above.
    let s: &[i32] = unsafe { core::slice::from_raw_parts(p, len) };
    let mut acc: i32 = 0;
    for (i, v) in s.iter().enumerate().rev() {
        acc = acc.wrapping_mul(2).wrapping_add(v.wrapping_mul(i as i32 + 1));
    }
    acc
}

/// `windows(2)`: a sliding pair. The window size is a nonzero constant, so the
/// `windows` precondition can never fail; a short slice simply yields no
/// iterations.
#[no_mangle]
pub extern "C" fn rust_slice_windows(p: *const i32, n: u32) -> i32 {
    if p.is_null() {
        return -1;
    }
    let len = clamp_len(n);
    // SAFETY: as above.
    let s: &[i32] = unsafe { core::slice::from_raw_parts(p, len) };
    let mut acc: i32 = 0;
    for w in s.windows(2) {
        acc = acc.wrapping_add(w[1].wrapping_sub(w[0]));
    }
    acc
}

/// `chunks(3)`: an uneven trailing chunk, so the loop has a remainder path. The
/// chunk size is a nonzero constant.
#[no_mangle]
pub extern "C" fn rust_slice_chunks(p: *const i32, n: u32) -> i32 {
    if p.is_null() {
        return -1;
    }
    let len = clamp_len(n);
    // SAFETY: as above.
    let s: &[i32] = unsafe { core::slice::from_raw_parts(p, len) };
    let mut acc: i32 = 0;
    for (ci, c) in s.chunks(3).enumerate() {
        let inner = c.iter().fold(0i32, |a, v| a.wrapping_add(*v));
        acc = acc.wrapping_add(inner.wrapping_mul(ci as i32 + 1));
    }
    acc
}

/// `split_at` + `zip`: two slices consumed in lockstep, so the loop trip count
/// is the MINIMUM of two lengths — a shape that is easy to decompile as the
/// wrong one of the two.
#[no_mangle]
pub extern "C" fn rust_slice_split_zip(p: *const i32, n: u32, at: u32) -> i32 {
    if p.is_null() {
        return -1;
    }
    let len = clamp_len(n);
    // SAFETY: as above.
    let s: &[i32] = unsafe { core::slice::from_raw_parts(p, len) };
    // `split_at` panics if the midpoint exceeds the length; reducing modulo
    // `len + 1` keeps it in [0, len] for every input.
    let mid = (at as usize) % (s.len() + 1);
    let (a, b) = s.split_at(mid);
    let mut acc: i32 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc = acc.wrapping_add(x.wrapping_mul(*y));
    }
    acc.wrapping_add(a.len() as i32).wrapping_sub(b.len() as i32)
}

/// Mutable slice: `iter_mut` writes back through the same fat pointer, so the
/// effect is observable as a buffer diff.
#[no_mangle]
pub extern "C" fn rust_slice_write(out: *mut i32, n: u32, k: i32) -> i32 {
    if out.is_null() {
        return -1;
    }
    let len = clamp_len(n);
    // SAFETY: caller owns >= 16 i32s at `out`; `len <= 16`.
    let s: &mut [i32] = unsafe { core::slice::from_raw_parts_mut(out, len) };
    let mut acc: i32 = 0;
    for (i, slot) in s.iter_mut().enumerate() {
        let v = slot.wrapping_mul(k).wrapping_add(i as i32);
        *slot = v;
        acc = acc.wrapping_add(v);
    }
    acc
}

/// In-place reverse via `swap`: two indexes into one mutable slice, the case a
/// decompiler must not turn into an aliasing violation.
#[no_mangle]
pub extern "C" fn rust_slice_reverse(out: *mut i32, n: u32) -> i32 {
    if out.is_null() {
        return -1;
    }
    let len = clamp_len(n);
    // SAFETY: as above.
    let s: &mut [i32] = unsafe { core::slice::from_raw_parts_mut(out, len) };
    s.reverse();
    s.iter()
        .fold(0i32, |a, v| a.wrapping_mul(3).wrapping_add(*v))
}
