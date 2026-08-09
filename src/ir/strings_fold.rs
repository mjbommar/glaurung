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
//! * Only folds when the recovered string is at least 3 characters and
//!   contains only printable ASCII / common whitespace.
//! * Caps the displayed length so enormous strings don't blow up the
//!   pseudocode; longer strings render as `"prefix..."` with an ellipsis.

use std::collections::HashMap;

use object::{Object, ObjectSection};

use crate::ir::ast::{Expr, Function, Stmt};

const MAX_STRING_LEN: usize = 256;
const MIN_STRING_LEN: usize = 3;

/// Build a VA → C-string map for every printable string the object's
/// rodata-like sections expose. Returns an empty map on parse failure.
pub fn collect_string_pool(data: &[u8]) -> HashMap<u64, String> {
    let mut out: HashMap<u64, String> = HashMap::new();
    let Ok(obj) = crate::decompile::profile::parse_object(data) else {
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
            if run.len() < MIN_STRING_LEN {
                continue;
            }
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
            // Suffixes are only indexed down to `MIN_STRING_LEN`, so this adds
            // at most `run.len()` entries and cannot manufacture one- or
            // two-character "strings" out of arbitrary integers.
            let mut offset = 1usize;
            while offset + MIN_STRING_LEN <= run.len() {
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
    fold_body(&mut f.body, pool);
}

fn fold_body(body: &mut [Stmt], pool: &HashMap<u64, String>) {
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
                        fold_constant_string(a, pool);
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
                fold_body(then_body, pool);
                if let Some(eb) = else_body {
                    fold_body(eb, pool);
                }
            }
            Stmt::While { cond, body } => {
                fold_expr(cond, pool);
                fold_body(body, pool);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                fold_body(std::slice::from_mut(init.as_mut()), pool);
                fold_expr(cond, pool);
                fold_body(body, pool);
                fold_body(std::slice::from_mut(step.as_mut()), pool);
            }
            Stmt::DoWhile { body, cond } => {
                fold_body(body, pool);
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
                    fold_body(body, pool);
                }
                if let Some(b) = default {
                    fold_body(b, pool);
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

fn fold_constant_string(expr: &mut Expr, pool: &HashMap<u64, String>) {
    let Expr::Const(value) = expr else {
        return;
    };
    let Ok(address) = u64::try_from(*value) else {
        return;
    };
    if let Some(string) = pool.get(&address) {
        *expr = Expr::StringLit {
            value: shorten(string),
        };
    }
}

fn fold_expr(e: &mut Expr, pool: &HashMap<u64, String>) {
    match e {
        Expr::Addr(v) => {
            if let Some(s) = pool.get(v) {
                *e = Expr::StringLit { value: shorten(s) };
            }
        }
        Expr::Named { va, .. } => {
            if let Some(s) = pool.get(va) {
                *e = Expr::StringLit { value: shorten(s) };
            }
        }
        Expr::Deref { addr, .. } => fold_expr(addr, pool),
        Expr::Bin { op, lhs, rhs } if matches!(op, crate::ir::types::BinOp::Add) => {
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
                if let Some(s) = pool.get(&va) {
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
        // Every value must be non-empty and purely printable.
        for v in pool.values() {
            assert!(!v.is_empty());
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

    /// Suffix indexing must not manufacture one- or two-character strings out of
    /// arbitrary integers that happen to land in rodata.
    #[test]
    fn suffix_indexing_respects_the_minimum_length() {
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples")
            .join("containers")
            .join("hello-cpp-g++-O0");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(&path).expect("read fixture");
        for (va, s) in collect_string_pool(&data) {
            assert!(
                s.len() >= MIN_STRING_LEN,
                "pool holds {s:?} at {va:#x}, shorter than the {MIN_STRING_LEN}-char floor"
            );
        }
    }
}
