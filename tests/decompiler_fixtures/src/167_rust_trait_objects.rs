// 167_rust_trait_objects.rs
//
// Rust dynamic dispatch through `&dyn Trait`. A trait object is a FAT POINTER:
// two machine words, (data pointer, vtable pointer). Unlike a C++ object, the
// vtable pointer is NOT stored in the object — it travels alongside it in the
// reference, so a `&dyn Op` passed by value occupies two registers and a
// `&[&dyn Op]` is an array of 16-byte pairs.
//
// The recovery signals:
//   * a virtual call is `call [rax + 8*k]` where rax is the SECOND half of a
//     pair the callee never loaded from the object;
//   * the Rust vtable layout is [drop_in_place, size, align, method0, method1,
//     ...], so the first user method sits at offset 24 on x86-64, not 0;
//   * unsizing a `&Concrete` to a `&dyn Op` is a pure compile-time act: it
//     materialises a pointer to a static vtable with no runtime work, so the
//     only evidence is a relocation into .data.rel.ro;
//   * `Box<dyn Op>` adds drop glue reached through vtable slot 0.
//
// Exposure: every driver is `#[no_mangle] pub extern "C" fn` over plain i32/u32
// scalars and caller-owned `*mut i32` buffers. Selectors are taken modulo the
// number of impls, counts are masked to <= 16, pointers are null-checked, and
// every arithmetic operation is `wrapping_*`. No input the harness can pass can
// panic or index out of bounds.
//
// Deterministic: the trait objects point at `static` instances or at freshly
// boxed values whose contents are a pure function of the arguments; no address
// is ever observed.

/// The object-safe trait. Two methods, so vtable slot ORDER matters: a
/// decompiler that swaps them produces a plausible-looking wrong answer.
trait Op {
    fn apply(&self, x: i32) -> i32;
    fn tag(&self) -> i32;
}

struct AddK {
    k: i32,
}
struct MulK {
    k: i32,
}
struct Clamp {
    lo: i32,
    hi: i32,
}
struct Affine {
    a: i32,
    b: i32,
}

impl Op for AddK {
    fn apply(&self, x: i32) -> i32 {
        x.wrapping_add(self.k)
    }
    fn tag(&self) -> i32 {
        11
    }
}

impl Op for MulK {
    fn apply(&self, x: i32) -> i32 {
        x.wrapping_mul(self.k)
    }
    fn tag(&self) -> i32 {
        22
    }
}

impl Op for Clamp {
    fn apply(&self, x: i32) -> i32 {
        if x < self.lo {
            self.lo
        } else if x > self.hi {
            self.hi
        } else {
            x
        }
    }
    fn tag(&self) -> i32 {
        33
    }
}

impl Op for Affine {
    fn apply(&self, x: i32) -> i32 {
        x.wrapping_mul(self.a).wrapping_add(self.b)
    }
    fn tag(&self) -> i32 {
        44
    }
}

static ADD7: AddK = AddK { k: 7 };
static MUL3: MulK = MulK { k: 3 };
static CLAMP: Clamp = Clamp { lo: -100, hi: 100 };
static AFFINE: Affine = Affine { a: 5, b: -9 };

/// Unsizing coercion site: four `&'static Concrete` values become
/// `&'static dyn Op` fat pointers, each pairing the same data pointer with a
/// different static vtable.
#[inline(never)]
fn choose(sel: u32) -> &'static dyn Op {
    match sel & 3 {
        0 => &ADD7,
        1 => &MUL3,
        2 => &CLAMP,
        _ => &AFFINE,
    }
}

/// One dynamic call through a fat pointer. `sel` is masked, so every input
/// selects a valid impl.
#[no_mangle]
pub extern "C" fn rust_dyn_apply(sel: u32, x: i32) -> i32 {
    choose(sel).apply(x)
}

/// Both vtable slots on the same object, so slot ordering is observable: a
/// decompiler that reads slot 3 where slot 4 belongs returns the other method's
/// value.
#[no_mangle]
pub extern "C" fn rust_dyn_two_slots(sel: u32, x: i32) -> i32 {
    let op = choose(sel);
    op.apply(x).wrapping_mul(100).wrapping_add(op.tag())
}

/// A fat pointer crossing a function boundary as an ARGUMENT: `op` arrives in
/// two registers and neither half is loaded from memory.
#[inline(never)]
fn twice(op: &dyn Op, x: i32) -> i32 {
    op.apply(op.apply(x))
}

#[no_mangle]
pub extern "C" fn rust_dyn_pass_fat(sel: u32, x: i32) -> i32 {
    twice(choose(sel), x)
}

/// A pipeline over an array of trait objects: the loop indexes 16-byte pairs,
/// reloading a different vtable each iteration, so the call target genuinely
/// varies at runtime and cannot be devirtualized.
#[no_mangle]
pub extern "C" fn rust_dyn_pipeline(x: i32, mask: u32) -> i32 {
    let ops: [&dyn Op; 4] = [&ADD7, &MUL3, &CLAMP, &AFFINE];
    let mut acc = x;
    for (i, op) in ops.iter().enumerate() {
        if mask & (1u32 << i) != 0 {
            acc = op.apply(acc);
        }
    }
    acc
}

/// Heap trait object. `Box<dyn Op>` is the same fat pointer, but dropping it
/// goes through vtable slot 0 (`drop_in_place`) plus the size/align slots, which
/// is the shape a decompiler most often mistakes for a data field.
#[inline(never)]
fn boxed(sel: u32, k: i32) -> Box<dyn Op> {
    match sel & 3 {
        0 => Box::new(AddK { k }),
        1 => Box::new(MulK { k }),
        2 => Box::new(Clamp {
            lo: -(k.wrapping_abs() & 0xff),
            hi: k.wrapping_abs() & 0xff,
        }),
        _ => Box::new(Affine {
            a: k,
            b: k.wrapping_neg(),
        }),
    }
}

/// The box is created, called through, and dropped inside the wrapper; only the
/// computed i32 escapes, so no address is ever observable.
#[no_mangle]
pub extern "C" fn rust_dyn_boxed(sel: u32, k: i32, x: i32) -> i32 {
    let op = boxed(sel, k);
    let r = op.apply(x).wrapping_add(op.tag());
    // `op` drops here: vtable slot 0 then the deallocation.
    r
}

/// Write one dynamic-dispatch result per element into a caller-owned buffer, so
/// the per-impl behaviour is visible as a buffer diff rather than a single
/// return value.
///
/// `out` is null-checked and `n` is clamped to the harness's 16-element buffer.
#[no_mangle]
pub extern "C" fn rust_dyn_fill(out: *mut i32, n: u32, x: i32) -> i32 {
    if out.is_null() {
        return -1;
    }
    let len = if n > 16 { 16 } else { n } as usize;
    // SAFETY: the caller owns at least 16 i32s at `out`; `len <= 16`.
    let dst: &mut [i32] = unsafe { core::slice::from_raw_parts_mut(out, len) };
    let mut sum: i32 = 0;
    for (i, slot) in dst.iter_mut().enumerate() {
        let op = choose(i as u32);
        let v = op.apply(x.wrapping_add(i as i32)).wrapping_add(op.tag());
        *slot = v;
        sum = sum.wrapping_add(v);
    }
    sum
}
