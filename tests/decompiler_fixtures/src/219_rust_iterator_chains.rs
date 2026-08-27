//! Iterator adapter chains — the single most idiomatic Rust codegen shape, and
//! one none of `166_*`..`171_*` covers.
//!
//! WHY IT IS ITS OWN PROBLEM. `values.iter().filter(..).map(..).sum()` is not a
//! library call at the machine level. Each adapter is a distinct zero-sized (or
//! closure-sized) type, `next()` is monomorphized per chain, and the optimiser
//! then fuses the whole pipeline into ONE loop — usually with the bounds check
//! elided, the closure inlined, and the `Option` discriminant folded into the
//! loop's exit test. What reaches the decompiler is a loop whose induction
//! variable, bound and body all came from different source constructs.
//!
//! At `-O0` none of that fusion happens: every adapter is a real struct, every
//! `next()` is a real call returning an `Option<T>` by value, and the chain is
//! a stack of nested calls. So the two lanes test opposite things — `O0` tests
//! whether a deep call chain over small aggregates is recovered, `O2` tests
//! whether the fused loop is recognised as a loop rather than as goto soup.
//!
//! `169_rust_slices_bounds` covers indexing a slice and the panic branch a
//! bounds check inserts; `166_rust_generics` covers monomorphization of a
//! generic function. Neither builds an adapter chain, so neither reaches the
//! `Iterator` trait's associated-type machinery or the closure environments the
//! adapters carry.
//!
//! Every function takes and returns plain integers so the harness can drive it
//! through the same differential as the C fixtures, and every input is bounded
//! in-source so no arithmetic can overflow (Rust panics on overflow in debug,
//! which would make the two lanes disagree for reasons unrelated to recovery).

/// A filter/map/sum pipeline over a slice built in-function.
#[no_mangle]
pub extern "C" fn iter_filter_map_sum(count: i32) -> i64 {
    if count < 0 || count > 64 {
        return -1;
    }
    let values: Vec<i64> = (0..count as i64).collect();
    values
        .iter()
        .filter(|v| **v % 3 != 0)
        .map(|v| v * 2)
        .sum::<i64>()
}

/// `enumerate` + `fold`: the index and the accumulator are both loop-carried,
/// and the closure captures nothing.
#[no_mangle]
pub extern "C" fn iter_enumerate_fold(count: i32) -> i64 {
    if count < 0 || count > 64 {
        return -1;
    }
    (0..count as i64)
        .enumerate()
        .fold(0i64, |acc, (i, v)| acc + (i as i64) * v)
}

/// `take_while` / `skip_while`: the exit condition is a closure rather than a
/// comparison against the length, so the fused loop's bound is data-dependent.
#[no_mangle]
pub extern "C" fn iter_take_skip(count: i32, limit: i32) -> i64 {
    if count < 0 || count > 64 || limit < 0 || limit > 64 {
        return -1;
    }
    let lim = limit as i64;
    (0..count as i64)
        .skip_while(|v| *v < lim / 2)
        .take_while(|v| *v < lim)
        .sum::<i64>()
}

/// `zip` of two ranges: two induction variables advanced together, with the
/// shorter one deciding the trip count.
#[no_mangle]
pub extern "C" fn iter_zip_dot(a_len: i32, b_len: i32) -> i64 {
    if a_len < 0 || a_len > 32 || b_len < 0 || b_len > 32 {
        return -1;
    }
    (0..a_len as i64)
        .zip((0..b_len as i64).map(|v| v * 3))
        .map(|(x, y)| x * y)
        .sum::<i64>()
}

/// `rev` + `chain`: a reversed range concatenated with a forward one, which
/// fuses into a single loop with two phases.
#[no_mangle]
pub extern "C" fn iter_rev_chain(count: i32) -> i64 {
    if count < 0 || count > 32 {
        return -1;
    }
    let n = count as i64;
    (0..n).rev().chain(0..n).map(|v| v + 1).sum::<i64>()
}

/// A closure that CAPTURES a local, so the adapter's environment is a real
/// field rather than a zero-sized type.
#[no_mangle]
pub extern "C" fn iter_capturing_closure(count: i32, scale: i32) -> i64 {
    if count < 0 || count > 64 {
        return -1;
    }
    let factor = (scale & 7) as i64 + 1;
    (0..count as i64).map(|v| v * factor).sum::<i64>()
}

/// CONTROL: the same arithmetic as `iter_filter_map_sum`, written as an
/// explicit loop. If this fails too, the defect is in loop recovery rather than
/// in the adapter chain.
#[no_mangle]
pub extern "C" fn explicit_loop_control(count: i32) -> i64 {
    if count < 0 || count > 64 {
        return -1;
    }
    let mut total: i64 = 0;
    let mut i: i64 = 0;
    while i < count as i64 {
        if i % 3 != 0 {
            total += i * 2;
        }
        i += 1;
    }
    total
}
