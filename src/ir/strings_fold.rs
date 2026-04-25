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
            Stmt::Assign { src, .. } => fold_expr(src, pool),
            Stmt::Store { addr, src } => {
                fold_expr(addr, pool);
                fold_expr(src, pool);
            }
            Stmt::Call { target, args } => {
                fold_expr(target, pool);
                for a in args {
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
            Stmt::Push { value } => fold_expr(value, pool),
            Stmt::Switch { discriminant, cases, default } => {
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
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
}

fn fold_expr(e: &mut Expr, pool: &HashMap<u64, String>) {
    match e {
        Expr::Addr(v) => {
            if let Some(s) = pool.get(v) {
                *e = Expr::StringLit {
                    value: shorten(s),
                };
            }
        }
        Expr::Named { va, .. } => {
            if let Some(s) = pool.get(va) {
                *e = Expr::StringLit {
                    value: shorten(s),
                };
            }
        }
        Expr::Deref { addr, .. } => fold_expr(addr, pool),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            fold_expr(lhs, pool);
            fold_expr(rhs, pool);
        }
        Expr::Un { src, .. } => fold_expr(src, pool),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::Lea { .. }
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
            assert!(v.chars().all(|c| c == '\t'
                || c == '\n'
                || c == '\r'
                || (' '..='~').contains(&c)));
        }
    }
}
