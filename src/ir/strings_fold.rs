//! Fold C-string literals into the AST.
//!
//! After [`super::name_resolve::resolve_names`] runs, `Expr::Named { va, .. }`
//! and `Expr::Addr(va)` carry concrete VAs. This pass walks the AST and,
//! whenever such a VA maps into a readable-data section of the binary whose
//! bytes form a printable UTF-8 C-string, replaces the expression with
//! `Expr::StringLit { value }`. The result is that
//!
//! ```text
//! %rdi = hello_str;
//! call puts(hello_str);
//! ```
//!
//! becomes
//!
//! ```text
//! %rdi = "hello, world\n";
//! call puts("hello, world\n");
//! ```
//!
//! when the `hello_str` symbol sits in `.rodata` and the bytes there are a
//! printable null-terminated string.
//!
//! Conservative by design:
//!
//! * Only folds addresses that resolve to a section named `.rodata`,
//!   `__cstring`, `__TEXT,__cstring`, or `.rdata` on PE.
//! * Only folds bytes that are printable ASCII / common whitespace.
//! * Caps the displayed length so enormous strings don't blow up the
//!   pseudocode; longer strings render as `"prefix..."` with an ellipsis.
//!
//! The `MIN_STRING_LEN` floor is a statement about **confidence in an address**,
//! not about the bytes, so it is enforced at the point of use rather than when
//! the pool is built:
//!
//! * a bare `Addr`/`Named` carries no type evidence, so it must be at least
//!   `MIN_STRING_LEN` characters — otherwise any integer that happens to point
//!   at a NUL byte would render as `""`;
//! * a call argument whose **callee prototype proves the parameter is
//!   `char *`** may go below the floor, because the type is authoritative.
//!   `setlocale(LC_ALL, "")` and `getopt(argc, argv, "a")` are real literals
//!   that the floor was discarding.

use std::collections::HashMap;

use object::{Object, ObjectSection};

use crate::ir::ast::{Expr, Function, Stmt};

const MAX_STRING_LEN: usize = 256;
const MIN_STRING_LEN: usize = 3;

/// Build a VA → C-string map for every printable string the object's
/// rodata-like sections expose. Returns an empty map on parse failure.
pub fn collect_string_pool(data: &[u8]) -> HashMap<u64, String> {
    let mut out: HashMap<u64, String> = HashMap::new();
    let Ok(obj) = object::read::File::parse(data) else {
        return out;
    };
    for section in obj.sections() {
        let name = section.name().unwrap_or("").to_ascii_lowercase();
        let rodata_like = name == ".rodata"
            || name == ".rdata"
            || name.contains("rodata")
            || name.contains("cstring")
            || name == "__cstring"
            || name == "__text.__cstring";
        if !rodata_like {
            continue;
        }
        let base = section.address();
        let Ok(bytes) = section.data() else {
            continue;
        };
        // Walk for null-terminated printable runs.
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            // Skip NULs until the next candidate string start.
            while cursor < bytes.len() && bytes[cursor] == 0 {
                cursor += 1;
            }
            let start = cursor;
            // Gather printable characters until NUL or section end.
            while cursor < bytes.len() && bytes[cursor] != 0 {
                cursor += 1;
            }
            let run = &bytes[start..cursor];
            if !is_printable_cstring(run) {
                continue;
            }
            let s = match std::str::from_utf8(run) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            let va = base.saturating_add(start as u64);
            out.entry(va).or_insert(s);

            // Index every suffix of the run as well, because linkers merge a
            // string that is a suffix of another into the same storage. In a
            // real `getconf`, `"%s = %lu\n"` sits at 0x3000 and `"%lu\n"` is
            // *the same bytes* at 0x3005 — there is no separate copy. Indexing
            // only run starts left every such reference rendering as a bare
            // integer (`printf((const char *)(0x3005), ...)`), which is most of
            // why string recovery read 1.52 per function against Ghidra's 5.63
            // on x86-64, where addresses already arrive complete.
            //
            // Suffixes are indexed all the way down to the empty string at the
            // run's NUL terminator. The `MIN_STRING_LEN` floor is NOT applied
            // here, because it is a statement about *confidence in an address*,
            // not about what the bytes are: `setlocale(LC_ALL, "")` and
            // `getopt(argc, argv, "a")` both pass genuine literals that the
            // floor discarded, and they rendered as `(const char *)(0x1ca2)`.
            // The floor now lives at the point of use — `fold_expr` keeps it for
            // a bare address, and only a callee prototype that proves the
            // parameter is `char *` may go below it. See `fold_constant_string`.
            let mut offset = 1usize;
            while offset <= run.len() {
                let tail = &run[offset..];
                if let Ok(t) = std::str::from_utf8(tail) {
                    let tail_va = base.saturating_add((start + offset) as u64);
                    out.entry(tail_va).or_insert_with(|| t.to_string());
                }
                offset += 1;
            }
        }
    }
    out
}

fn is_printable_cstring(bytes: &[u8]) -> bool {
    let mut printable = 0usize;
    for &b in bytes {
        let ok = b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b);
        if !ok {
            return false;
        }
        if !b.is_ascii_whitespace() {
            printable += 1;
        }
    }
    // Reject strings that are all whitespace.
    printable >= 1
}

fn shorten(s: &str) -> String {
    if s.len() <= MAX_STRING_LEN {
        s.to_string()
    } else {
        let mut out = s[..MAX_STRING_LEN].to_string();
        out.push_str("...");
        out
    }
}

/// Run string-literal folding over `f` using the provided string pool.
pub fn fold_string_literals(f: &mut Function, pool: &HashMap<u64, String>) {
    if pool.is_empty() {
        return;
    }
    let defs = constant_definitions(&f.body);
    fold_body(&mut f.body, pool, &defs);
}

/// Map each name that is assigned exactly once, to a constant value, back to
/// that constant.
///
/// Names are still SSA-versioned at this point (`%x22#2`), so "assigned once"
/// is normally structural — but a name assigned twice is recorded as ambiguous
/// and dropped rather than resolved to whichever definition happened to come
/// last. Only used from the contract-proven `char *` path, so a wrong answer
/// here cannot invent a string in an untyped position.
fn constant_definitions(body: &[Stmt]) -> HashMap<String, i64> {
    let mut seen: HashMap<String, Option<i64>> = HashMap::new();
    collect_constant_definitions(body, &mut seen);
    seen.into_iter()
        .filter_map(|(name, value)| value.map(|v| (name, v)))
        .collect()
}

fn collect_constant_definitions(body: &[Stmt], out: &mut HashMap<String, Option<i64>>) {
    // Two passes' worth of information in one: `resolved` lets a definition
    // refer to an earlier constant definition (`%x22#1 = 0x1000` then
    // `%x22#2 = %x22#1 + 3313`), which is exactly the AArch64 adrp/add shape.
    for s in body {
        match s {
            Stmt::Assign { dst, src } => {
                let resolved: HashMap<String, i64> = out
                    .iter()
                    .filter_map(|(k, v)| v.map(|v| (k.clone(), v)))
                    .collect();
                let value = const_address(src, &resolved);
                out.entry(dst.to_string())
                    .and_modify(|slot| *slot = None) // assigned more than once
                    .or_insert(value);
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_constant_definitions(then_body, out);
                if let Some(eb) = else_body {
                    collect_constant_definitions(eb, out);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_constant_definitions(body, out)
            }
            Stmt::For {
                init, step, body, ..
            } => {
                collect_constant_definitions(std::slice::from_ref(init.as_ref()), out);
                collect_constant_definitions(body, out);
                collect_constant_definitions(std::slice::from_ref(step.as_ref()), out);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases {
                    collect_constant_definitions(b, out);
                }
                if let Some(b) = default {
                    collect_constant_definitions(b, out);
                }
            }
            _ => {}
        }
    }
}

fn fold_body(body: &mut [Stmt], pool: &HashMap<u64, String>, defs: &HashMap<String, i64>) {
    for s in body.iter_mut() {
        match s {
            Stmt::IndirectGoto { target } => fold_expr(target, pool),
            Stmt::Assign { src, .. } => fold_expr(src, pool),
            Stmt::Store { addr, src, .. } => {
                fold_expr(addr, pool);
                fold_expr(src, pool);
            }
            Stmt::Call { target, args, .. } => {
                let character_pointer_params = match target {
                    Expr::Named { name, .. } => crate::ir::call_contracts::lookup(name)
                        .map(|contract| {
                            contract
                                .params
                                .iter()
                                .map(|parameter| is_character_pointer(&parameter.c_type))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                    _ => Vec::new(),
                };
                fold_expr(target, pool);
                for (index, a) in args.iter_mut().enumerate() {
                    if character_pointer_params.get(index) == Some(&true) {
                        fold_constant_string(a, pool, defs);
                    }
                    fold_expr(a, pool);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    fold_expr(e, pool);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                fold_expr(cond, pool);
                fold_body(then_body, pool, defs);
                if let Some(eb) = else_body {
                    fold_body(eb, pool, defs);
                }
            }
            Stmt::While { cond, body } => {
                fold_expr(cond, pool);
                fold_body(body, pool, defs);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                fold_body(std::slice::from_mut(init.as_mut()), pool, defs);
                fold_expr(cond, pool);
                fold_body(body, pool, defs);
                fold_body(std::slice::from_mut(step.as_mut()), pool, defs);
            }
            Stmt::DoWhile { body, cond } => {
                fold_body(body, pool, defs);
                fold_expr(cond, pool);
            }
            Stmt::Push { value } => fold_expr(value, pool),
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                fold_expr(discriminant, pool);
                for (_, body) in cases.iter_mut() {
                    fold_body(body, pool, defs);
                }
                if let Some(b) = default {
                    fold_body(b, pool, defs);
                }
            }
            Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {}
        }
    }
}

fn is_character_pointer(c_type: &str) -> bool {
    matches!(c_type.trim(), "char *" | "const char *" | "char *const")
}

/// Evaluate an expression that is a compile-time constant address.
///
/// AArch64 forms an address as `adrp` + `add`, which arrives here as
/// `Bin(Add, Const(page), Const(offset))` — never a bare `Const`, because the
/// two halves are separate instructions and the algebraic folder leaves the sum
/// alone. Requiring `Expr::Const` therefore discarded every AArch64 literal
/// before the length floor was even consulted. `defs` resolves a versioned name
/// back to its single defining constant, which is the other AArch64 shape:
/// `%x22#2 = (%x22#1 + 3313)` used later as `getopt(..., %x22#2)`.
fn const_address(e: &Expr, defs: &HashMap<String, i64>) -> Option<i64> {
    match e {
        Expr::Const(v) => Some(*v),
        // `adrp` lifts to `Addr`, not `Const` — it renders as a bare hex number,
        // which makes the two indistinguishable in a pass dump.
        Expr::Addr(v) => i64::try_from(*v).ok(),
        Expr::Reg(r) => defs.get(&r.to_string()).copied(),
        Expr::Cast { expr, .. } => const_address(expr, defs),
        Expr::Bin {
            op: crate::ir::types::BinOp::Add,
            lhs,
            rhs,
        } => const_address(lhs, defs)?.checked_add(const_address(rhs, defs)?),
        _ => None,
    }
}

/// Fold a value in a position a callee prototype proves is `char *`.
///
/// This is the only path allowed below `MIN_STRING_LEN`. The floor exists so an
/// arbitrary small integer cannot become a string; here the parameter's type is
/// authoritative, so `""`, `"a"` and `"%d"` are recoverable — and they are real
/// literals (`setlocale(LC_ALL, "")`, `getopt(argc, argv, "a")`) that the floor
/// was silently discarding.
fn fold_constant_string(expr: &mut Expr, pool: &HashMap<u64, String>, defs: &HashMap<String, i64>) {
    let Some(value) = const_address(expr, defs) else {
        return;
    };
    let Ok(address) = u64::try_from(value) else {
        return;
    };
    if let Some(string) = pool.get(&address) {
        *expr = Expr::StringLit {
            value: shorten(string),
        };
    }
}

/// A bare address carries no type evidence, so the confidence floor applies:
/// an address pointing at a NUL byte must not silently become `""`.
fn confident_string(pool: &HashMap<u64, String>, va: u64) -> Option<&String> {
    pool.get(&va).filter(|s| s.len() >= MIN_STRING_LEN)
}

fn fold_expr(e: &mut Expr, pool: &HashMap<u64, String>) {
    match e {
        Expr::Addr(v) => {
            if let Some(s) = confident_string(pool, *v) {
                *e = Expr::StringLit { value: shorten(s) };
            }
        }
        Expr::Named { va, .. } => {
            if let Some(s) = confident_string(pool, *va) {
                *e = Expr::StringLit { value: shorten(s) };
            }
        }
        Expr::Deref { addr, .. } => fold_expr(addr, pool),
        Expr::Bin {
            op: crate::ir::types::BinOp::Add,
            lhs,
            rhs,
        } => {
            // AArch64 (and ARM32) build the address of a string in two
            // instructions: `adrp` supplies the 4 KiB page and a following
            // `add` supplies the low 12 bits. This pass runs before the
            // algebraic folder, so at this point the value is still
            // `Addr(page) + Const(offset)` rather than one address, and every
            // string reference on those targets used to slip through — measured
            // as 0.00 string literals per function on both ARM targets against
            // Ghidra's 5.68.
            //
            // x86-64 needs none of this: `lea rax, [rip+disp]` is one
            // instruction and arrives as a complete `Expr::Addr`.
            let combined = match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::Addr(base), Expr::Const(off)) | (Expr::Const(off), Expr::Addr(base)) => {
                    base.checked_add_signed(*off)
                }
                _ => None,
            };
            if let Some(va) = combined {
                if let Some(s) = confident_string(pool, va) {
                    *e = Expr::StringLit { value: shorten(s) };
                    return;
                }
            }
            fold_expr(lhs, pool);
            fold_expr(rhs, pool);
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            fold_expr(lhs, pool);
            fold_expr(rhs, pool);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            fold_expr(cond, pool);
            fold_expr(if_true, pool);
            fold_expr(if_false, pool);
        }
        Expr::Un { src, .. } => fold_expr(src, pool),
        Expr::Cast { expr, .. } => fold_expr(expr, pool),
        Expr::FunctionTableEntry { index, .. } => fold_expr(index, pool),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                fold_expr(argument, pool);
            }
        }
        Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};
    use crate::ir::types::VReg;

    #[test]
    fn named_addr_in_call_arg_gets_folded_to_literal() {
        let mut pool = HashMap::new();
        pool.insert(0x2008, "hello, world\n".to_string());
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0x11f0,
                    name: "puts".into(),
                },
                args: vec![Expr::Named {
                    va: 0x2008,
                    name: "hello_str".into(),
                }],
                dst: None,
                call_spec: None,
            }],
        };
        fold_string_literals(&mut f, &pool);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(
                args[0],
                Expr::StringLit {
                    value: "hello, world\n".to_string(),
                }
            );
        } else {
            panic!("expected Call");
        }
    }

    #[test]
    fn assign_rhs_addr_also_folds() {
        let mut pool = HashMap::new();
        pool.insert(0x3000, "fmt %d\n".to_string());
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("rdi"),
                src: Expr::Addr(0x3000),
            }],
        };
        fold_string_literals(&mut f, &pool);
        match &f.body[0] {
            Stmt::Assign { src, .. } => assert_eq!(
                *src,
                Expr::StringLit {
                    value: "fmt %d\n".to_string()
                }
            ),
            _ => unreachable!(),
        }
    }

    #[test]
    fn constant_call_argument_folds_only_for_authoritative_character_pointer() {
        let mut pool = HashMap::new();
        pool.insert(0x402004, "known".to_string());
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1060,
                        name: "strcmp".into(),
                    },
                    args: vec![Expr::Reg(VReg::phys("rdi")), Expr::Const(0x402004)],
                    dst: Some(VReg::phys("rax")),
                    call_spec: None,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1070,
                        name: "memset".into(),
                    },
                    args: vec![Expr::Const(0x402004), Expr::Const(0), Expr::Const(5)],
                    dst: Some(VReg::phys("rax")),
                    call_spec: None,
                },
            ],
        };

        fold_string_literals(&mut f, &pool);

        let Stmt::Call { args, .. } = &f.body[0] else {
            panic!("expected strcmp call");
        };
        assert_eq!(
            args[1],
            Expr::StringLit {
                value: "known".to_string()
            }
        );
        let Stmt::Call { args, .. } = &f.body[1] else {
            panic!("expected memset call");
        };
        assert_eq!(args[0], Expr::Const(0x402004));
    }

    #[test]
    fn unknown_addr_stays_unchanged() {
        let pool: HashMap<u64, String> = HashMap::new();
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("rdi"),
                src: Expr::Addr(0x2008),
            }],
        };
        fold_string_literals(&mut f, &pool);
        match &f.body[0] {
            Stmt::Assign { src, .. } => assert_eq!(*src, Expr::Addr(0x2008)),
            _ => unreachable!(),
        }
    }

    #[test]
    fn is_printable_rejects_non_ascii_binary() {
        assert!(!is_printable_cstring(b"\xff\xfe\x00"));
        assert!(!is_printable_cstring(b"\x01\x02"));
        assert!(is_printable_cstring(b"hello"));
        assert!(is_printable_cstring(b"line\nwith newline"));
    }

    #[test]
    fn is_printable_rejects_all_whitespace() {
        assert!(!is_printable_cstring(b"   \t\n"));
    }

    #[test]
    fn collect_string_pool_finds_strings_in_real_binary() {
        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let pool = collect_string_pool(&data);
        // The committed hello sample has *some* readable strings in rodata
        // (glibc init stubs include argv0 reference strings etc.). If this
        // fails we've broken section iteration.
        assert!(!pool.is_empty(), "no strings recovered from hello-gcc-O2");
        // Every value must be purely printable. Values may now be short — even
        // empty, at a run's NUL terminator — because the length floor is
        // applied where an address is used, not when the pool is built.
        for v in pool.values() {
            assert!(v
                .chars()
                .all(|c| c == '\t' || c == '\n' || c == '\r' || (' '..='~').contains(&c)));
        }
    }

    /// Linkers merge a string that is a suffix of another into shared storage,
    /// so a reference can legitimately point into the middle of a run.
    ///
    /// In this real binary `"%s = %lu\n"` lives at 0x3000 and `"%lu\n"` is the
    /// same bytes at 0x3005 — there is no second copy. Indexing only run starts
    /// left every such call rendering as `printf((const char *)(0x3005), ...)`.
    #[test]
    fn suffix_merged_strings_are_indexed() {
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples")
            .join("containers")
            .join("hello-cpp-g++-O0");
        if !path.exists() {
            eprintln!("skipping suffix-string test: {} absent", path.display());
            return;
        }
        let data = std::fs::read(&path).expect("read fixture");
        let pool = collect_string_pool(&data);
        assert!(!pool.is_empty(), "fixture produced no strings at all");

        // For every indexed string long enough to have one, its own one-character
        // suffix must also be indexed and must be exactly that suffix.
        let mut checked = 0usize;
        for (va, s) in &pool {
            if s.len() <= MIN_STRING_LEN || !s.is_char_boundary(1) {
                continue;
            }
            let tail_va = va + 1;
            if let Some(tail) = pool.get(&tail_va) {
                assert_eq!(
                    tail.as_str(),
                    &s[1..],
                    "suffix at {tail_va:#x} does not match the tail of {va:#x}"
                );
                checked += 1;
            }
        }
        assert!(
            checked > 0,
            "no suffix entries were indexed; merged-string references cannot resolve"
        );
    }

    /// An address with no type evidence must never fold below the confidence
    /// floor, even though the pool now holds short entries. This is the check
    /// that stops an arbitrary integer landing in rodata from rendering as
    /// `""` or `"a"`.
    #[test]
    fn an_untyped_address_never_folds_below_the_minimum_length() {
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples")
            .join("containers")
            .join("hello-cpp-g++-O0");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(&path).expect("read fixture");
        let pool = collect_string_pool(&data);
        let short: Vec<_> = pool
            .iter()
            .filter(|(_, s)| s.len() < MIN_STRING_LEN)
            .collect();
        assert!(
            !short.is_empty(),
            "fixture has no short entries, so this test would pass vacuously"
        );
        for (va, s) in short {
            assert!(
                confident_string(&pool, *va).is_none(),
                "untyped address {va:#x} folded to the short string {s:?}"
            );
            // ...but the same address IS recoverable where a prototype proves
            // the parameter is `char *`.
            let mut e = Expr::Const(*va as i64);
            fold_constant_string(&mut e, &pool, &HashMap::new());
            assert_eq!(
                e,
                Expr::StringLit {
                    value: s.to_string()
                },
                "proven char* position failed to recover {s:?} at {va:#x}"
            );
        }
    }

    /// The AArch64 shape: the address never arrives as a bare `Const`. It is
    /// either an unfolded `adrp`+`add` sum, or a name defined by one.
    #[test]
    fn a_proven_char_pointer_resolves_an_aarch64_split_address() {
        use crate::ir::types::{BinOp, VReg};

        let mut pool = HashMap::new();
        pool.insert(0x1ca2u64, String::new()); // setlocale(LC_ALL, "")
        pool.insert(0x1cf1u64, "a".to_string()); // getopt(argc, argv, "a")

        // adrp + add, still unfolded at this point in the pipeline.
        let mut sum = Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::Const(0x1000)),
            rhs: Box::new(Expr::Const(0xca2)),
        };
        fold_constant_string(&mut sum, &pool, &HashMap::new());
        assert_eq!(
            sum,
            Expr::StringLit {
                value: String::new()
            }
        );

        // The same address reaching the call through a single-assignment name.
        // Key derived from Display so the map cannot drift from the lookup.
        let defs = HashMap::from([(VReg::phys("x22#2").to_string(), 0x1cf1i64)]);
        let mut via_reg = Expr::Reg(VReg::phys("x22#2"));
        fold_constant_string(&mut via_reg, &pool, &defs);
        assert_eq!(
            via_reg,
            Expr::StringLit {
                value: "a".to_string()
            }
        );

        // A name with no constant definition is left alone.
        let mut unknown = Expr::Reg(VReg::phys("x9#1"));
        fold_constant_string(&mut unknown, &pool, &defs);
        assert_eq!(unknown, Expr::Reg(VReg::phys("x9#1")));
    }

    /// The pool must key on the same address space the AST uses, for every
    /// container — not just ELF. A PE's `.rdata` is described by an RVA in the
    /// section header, but the decompiler works in image-based VAs, so a pool
    /// keyed on RVAs would silently miss every Windows string.
    #[test]
    fn the_pool_keys_pe_strings_on_image_based_virtual_addresses() {
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/windows/vendor/realworld/sqfs-amd-clinfo.exe");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(&path).expect("read fixture");
        let pool = collect_string_pool(&data);
        assert!(!pool.is_empty(), "no strings recovered from a real PE");
        // This image is based at 0x140000000; `.rdata` sits at RVA 0x2a000.
        // Keys must be the sum, not the RVA.
        let lowest = *pool.keys().min().expect("non-empty");
        assert!(
            lowest >= 0x1_4000_0000,
            "pool keyed on RVAs, not image-based VAs: lowest key {lowest:#x}"
        );
    }

    /// A name assigned twice is ambiguous and must not resolve to whichever
    /// definition happened to be seen last.
    #[test]
    fn a_name_assigned_twice_is_not_treated_as_constant() {
        use crate::ir::types::VReg;

        let body = vec![
            Stmt::Assign {
                dst: VReg::phys("x0"),
                src: Expr::Const(0x1ca2),
            },
            Stmt::Assign {
                dst: VReg::phys("x0"),
                src: Expr::Const(0x9999),
            },
        ];
        assert!(!constant_definitions(&body).contains_key("x0"));
    }
}
