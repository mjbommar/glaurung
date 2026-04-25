//! Recognise the stack-canary idiom and a small handful of other well-known
//! x86-64 TLS loads, rewriting them into named references.
//!
//! On x86-64 Linux and glibc-based systems, `gcc -fstack-protector` emits:
//!
//! ```text
//!   mov rax, fs:[0x28]          ; load canary from thread-local storage
//!   mov [rsp + N], rax          ; stash it on the stack
//!   ...                         ; function body
//!   mov rcx, [rsp + N]          ; reload canary
//!   xor rcx, fs:[0x28]          ; compare against original
//!   jne __stack_chk_fail
//! ```
//!
//! Our lifter drops the `fs:` segment override so the TLS load appears in
//! the AST as `*(u64)&[0x28]` — a deref of the literal address `0x28`. The
//! offset `0x28` is, in practice, only used for the canary; no legitimate
//! program loads from an absolute VA of `0x28`. This pass pattern-matches
//! that specific shape and rewrites it to a named `__stack_chk_guard`.
//!
//! The same pattern-match also applies to Windows `gs:[0x28]` (MSVC and
//! mingw) for hardened binaries, so the rule is simply: deref of
//! `[constant 0x28]` → `__stack_chk_guard`.

use crate::ir::ast::{Expr, Function, Stmt};

const CANARY_DISP: i64 = 0x28;
const CANARY_NAME: &str = "__stack_chk_guard";

/// Additional well-known TLS offsets — stable across glibc versions and
/// safe to label without risking false positives.
///
/// * `fs:0x00` — `tcbhead_t` self pointer. Loaded by `pthread_self()` and
///   by TLS-descriptor address resolution. Many functions read it to pass
///   to threading helpers.
/// * `fs:0x30` — `__pointer_chk_guard`, GCC's pointer-mangling cookie used
///   for `setjmp` / `longjmp` to XOR-scramble return addresses.
///
/// Only entries that are unambiguous and widely documented belong here.
/// Anything implementation-private should stay as the raw `fs:&[off]`
/// form so a reader knows it's unresolved.
const KNOWN_TLS_OFFSETS: &[(i64, &str)] = &[
    (0x00, "__tls_self"),
    (0x30, "__pointer_chk_guard"),
];

/// Rewrite every TLS canary load in `f` to reference `__stack_chk_guard`.
///
/// Only the TLS-deref renaming runs here. The prologue-save collapse is a
/// separate entry point ([`collapse_canary_save`]) that must run AFTER
/// stack-local promotion and role-register naming, because it looks for
/// the `%ret = __stack_chk_guard; store %stack_N = %ret;` pair which
/// only takes that shape post-naming.
pub fn recognise_canary(f: &mut Function) {
    rewrite_body(&mut f.body);
}

/// Second-phase canary pass: collapse the prologue save pair
/// `%reg = __stack_chk_guard; store %stack_N = %reg;` into a single
/// `// stack canary: save guard to %stack_N` comment and, when the
/// matching exit-check shape is present, collapse that too.
pub fn collapse_canary_save(f: &mut Function) {
    collapse_body(&mut f.body);
    // If the prologue save comment is now present, try to collapse the
    // corresponding exit check shape(s).
    if let Some(slot) = find_canary_slot(&f.body) {
        collapse_exit_check(&mut f.body, &slot);
    }
}

fn find_canary_slot(body: &[Stmt]) -> Option<String> {
    for s in body {
        if let Stmt::Comment(c) = s {
            if let Some(rest) = c.strip_prefix("stack canary: save guard to %") {
                return Some(rest.to_string());
            }
        }
    }
    None
}

/// Fold `%reg = %stack_N;` immediately followed by `if (cond) { goto L_X; }`
/// into a single `// stack-canary check` comment. The branch to the
/// `__stack_chk_fail` target is preserved — only the reload-and-compare
/// scaffolding collapses.
fn collapse_exit_check(body: &mut Vec<Stmt>, slot: &str) {
    // Recurse into nested arms first.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_exit_check(then_body, slot);
                if let Some(eb) = else_body {
                    collapse_exit_check(eb, slot);
                }
            }
            Stmt::While { body, .. } => collapse_exit_check(body, slot),
            _ => {}
        }
    }

    let mut i = 0;
    while i + 1 < body.len() {
        // Reload: `%X = %stack_N`.
        let reload = match &body[i] {
            Stmt::Assign {
                dst: crate::ir::types::VReg::Phys(dst_name),
                src: Expr::Reg(crate::ir::types::VReg::Phys(s)),
            } if s == slot => Some(dst_name.clone()),
            _ => None,
        };
        let Some(reloaded_reg) = reload else {
            i += 1;
            continue;
        };

        // Optional arithmetic step: `%X = (%X op __stack_chk_guard)`. The
        // compiler typically emits sub / xor to compare the canary. We
        // accept any BinOp; the essential signal is that the RHS mentions
        // `__stack_chk_guard`.
        let mut end = i + 1;
        let has_compare_step = matches!(
            &body[end],
            Stmt::Assign {
                dst: crate::ir::types::VReg::Phys(d),
                src: Expr::Bin { lhs, rhs, .. },
            } if d == &reloaded_reg
                && (expr_mentions_guard(lhs) || expr_mentions_guard(rhs))
        );
        if has_compare_step {
            end += 1;
        }

        // Branch: `if (cond) { goto L; }` with a single-stmt then-arm.
        if end >= body.len() {
            i += 1;
            continue;
        }
        let is_branch = matches!(
            &body[end],
            Stmt::If {
                cond: _,
                then_body,
                else_body: None,
            } if then_body.len() == 1
                && matches!(&then_body[0], Stmt::Goto { .. })
        );
        if is_branch {
            body.drain(i..=end);
            body.insert(i, Stmt::Comment("stack-canary check".to_string()));
        }
        i += 1;
    }
}

fn expr_mentions_guard(e: &Expr) -> bool {
    match e {
        Expr::Named { name, .. } => name == CANARY_NAME,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_mentions_guard(lhs) || expr_mentions_guard(rhs)
        }
        Expr::Un { src, .. } => expr_mentions_guard(src),
        Expr::Deref { addr, .. } => expr_mentions_guard(addr),
        _ => false,
    }
}

fn collapse_body(body: &mut Vec<Stmt>) {
    // Recurse into structured arms so nested prologue shapes collapse too
    // (unlikely in practice, but symmetric with the ARM64 pass).
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_body(then_body);
                if let Some(eb) = else_body {
                    collapse_body(eb);
                }
            }
            Stmt::While { body, .. } => collapse_body(body),
            _ => {}
        }
    }

    let mut i = 0;
    while i + 1 < body.len() {
        let load = matches!(
            &body[i],
            Stmt::Assign {
                dst: crate::ir::types::VReg::Phys(_),
                src: Expr::Named { name, .. },
            } if name == CANARY_NAME
        );
        if !load {
            i += 1;
            continue;
        }
        let Stmt::Assign { dst: load_dst, .. } = &body[i] else {
            i += 1;
            continue;
        };
        let load_dst = load_dst.clone();
        // Next stmt must store that register to a %stack_* slot.
        let store_match = match &body[i + 1] {
            Stmt::Store {
                addr: Expr::Reg(crate::ir::types::VReg::Phys(slot)),
                src: Expr::Reg(src),
            } if slot.starts_with("stack_") && src == &load_dst => Some(slot.clone()),
            _ => None,
        };
        if let Some(slot) = store_match {
            body.remove(i + 1);
            body[i] = Stmt::Comment(format!(
                "stack canary: save guard to %{}",
                slot
            ));
        }
        i += 1;
    }
}

fn rewrite_body(body: &mut [Stmt]) {
    for s in body.iter_mut() {
        match s {
            Stmt::Assign { src, .. } => rewrite_expr(src),
            Stmt::Store { addr, src } => {
                rewrite_expr(addr);
                rewrite_expr(src);
            }
            Stmt::Call { target, args } => {
                rewrite_expr(target);
                for a in args {
                    rewrite_expr(a);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    rewrite_expr(e);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                rewrite_expr(cond);
                rewrite_body(then_body);
                if let Some(eb) = else_body {
                    rewrite_body(eb);
                }
            }
            Stmt::While { cond, body } => {
                rewrite_expr(cond);
                rewrite_body(body);
            }
            Stmt::Push { value } => rewrite_expr(value),
            Stmt::Switch { discriminant, cases, default } => {
                rewrite_expr(discriminant);
                for (_, body) in cases.iter_mut() {
                    rewrite_body(body);
                }
                if let Some(b) = default {
                    rewrite_body(b);
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

fn rewrite_expr(e: &mut Expr) {
    match e {
        // Canonical shape: deref of a base-less/index-less Lea with a known
        // TLS displacement and a matching segment override.
        Expr::Deref { addr, .. } => {
            if let Some((disp, name)) = known_tls_load(addr) {
                *e = Expr::Named {
                    va: disp as u64,
                    name: name.to_string(),
                };
                return;
            }
            rewrite_expr(addr);
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            rewrite_expr(lhs);
            rewrite_expr(rhs);
        }
        Expr::Un { src, .. } => rewrite_expr(src),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Lea { .. }
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
    }
}

/// Match a TLS load shape (`fs:&[disp]` or `gs:&[disp]`) against the
/// canary and the small `KNOWN_TLS_OFFSETS` table. Returns `(disp, name)`
/// when the address is recognised.
fn known_tls_load(addr: &Expr) -> Option<(i64, &'static str)> {
    if let Expr::Lea {
        base: None,
        index: None,
        disp,
        segment,
        ..
    } = addr
    {
        // Only accept explicit TLS segments. ARM64 and plain x86 loads from
        // absolute address 0x28 are correctly left untouched.
        if !matches!(segment.as_deref(), Some("fs") | Some("gs")) {
            return None;
        }
        if *disp == CANARY_DISP {
            return Some((CANARY_DISP, CANARY_NAME));
        }
        for (off, name) in KNOWN_TLS_OFFSETS {
            if *disp == *off {
                return Some((*off, *name));
            }
        }
    }
    None
}

/// True when `addr` is the stack-canary TLS load specifically.
fn is_canary_addr(addr: &Expr) -> bool {
    matches!(known_tls_load(addr), Some((CANARY_DISP, _)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, Function, Stmt};
    use crate::ir::types::VReg;

    fn lea_abs(disp: i64) -> Expr {
        lea_abs_seg(disp, Some("fs".to_string()))
    }

    fn lea_abs_seg(disp: i64, segment: Option<String>) -> Expr {
        Expr::Lea {
            base: None,
            index: None,
            scale: 0,
            disp,
            segment,
        }
    }

    #[test]
    fn canary_load_is_renamed() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("rax"),
                src: Expr::Deref {
                    addr: Box::new(lea_abs(0x28)),
                    size: 8,
                },
            }],
        };
        recognise_canary(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(
                *src,
                Expr::Named {
                    va: 0x28,
                    name: "__stack_chk_guard".to_string(),
                }
            );
        }
    }

    #[test]
    fn non_canary_deref_is_unchanged() {
        // Deref of an unknown absolute TLS offset must not fire.
        // 0x88 is arbitrary — chosen to sit outside our known-offsets table.
        let orig = Expr::Deref {
            addr: Box::new(lea_abs(0x88)),
            size: 8,
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("rax"),
                src: orig.clone(),
            }],
        };
        recognise_canary(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, orig);
        }
    }

    #[test]
    fn tls_pointer_chk_guard_offset_is_recognised() {
        // fs:[0x30] = __pointer_chk_guard.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("rax"),
                src: Expr::Deref {
                    addr: Box::new(lea_abs(0x30)),
                    size: 8,
                },
            }],
        };
        recognise_canary(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(
                *src,
                Expr::Named {
                    va: 0x30,
                    name: "__pointer_chk_guard".to_string(),
                }
            );
        }
    }

    #[test]
    fn unknown_tls_offset_is_not_renamed() {
        // fs:[0x50] — not in our table, must stay raw.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("rax"),
                src: Expr::Deref {
                    addr: Box::new(lea_abs(0x50)),
                    size: 8,
                },
            }],
        };
        let orig = f.clone();
        recognise_canary(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn abs_load_without_segment_is_not_canary() {
        // Same disp, no segment → not canary. Precision check.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("rax"),
                src: Expr::Deref {
                    addr: Box::new(lea_abs_seg(0x28, None)),
                    size: 8,
                },
            }],
        };
        let orig = f.clone();
        recognise_canary(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn deref_with_base_is_not_canary() {
        // `[%rbp + 0x28]` is a stack-slot load, not the canary.
        let addr = Expr::Lea {
            base: Some(VReg::phys("rbp")),
            index: None,
            scale: 0,
            disp: 0x28,
            segment: None,
        };
        let orig = Expr::Deref {
            addr: Box::new(addr),
            size: 8,
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("rax"),
                src: orig.clone(),
            }],
        };
        recognise_canary(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, orig);
        }
    }

    #[test]
    fn prologue_canary_save_pair_collapses_to_comment() {
        use crate::ir::types::VReg;
        let mut f = Function {
            name: "main".into(),
            entry_va: 0,
            body: vec![
                // %rax = __stack_chk_guard;
                Stmt::Assign {
                    dst: VReg::phys("rax"),
                    src: Expr::Deref {
                        addr: Box::new(lea_abs(0x28)),
                        size: 8,
                    },
                },
                // store %stack_0 = %rax;
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("stack_0")),
                    src: Expr::Reg(VReg::phys("rax")),
                },
            ],
        };
        recognise_canary(&mut f);
        collapse_canary_save(&mut f);
        assert_eq!(f.body.len(), 1);
        assert!(matches!(
            &f.body[0],
            Stmt::Comment(s) if s.contains("stack canary") && s.contains("stack_0")
        ));
    }

    #[test]
    fn canary_exit_check_collapses_when_save_comment_present() {
        use crate::ir::types::VReg;
        let mut f = Function {
            name: "main".into(),
            entry_va: 0,
            body: vec![
                Stmt::Comment("stack canary: save guard to %stack_0".to_string()),
                // ... function body ...
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1080,
                        name: "puts".into(),
                    },
                    args: vec![],
                },
                // Exit-check shape:
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Reg(VReg::phys("stack_0")),
                },
                Stmt::If {
                    cond: Expr::Reg(VReg::Flag(crate::ir::types::Flag::Z)),
                    then_body: vec![Stmt::Goto { target: 0x1227 }],
                    else_body: None,
                },
                Stmt::Return { value: None },
            ],
        };
        collapse_canary_save(&mut f);
        // Expect: save comment, call, check comment, return.
        assert_eq!(f.body.len(), 4, "got: {:?}", f.body);
        assert!(matches!(&f.body[0], Stmt::Comment(s) if s.contains("save guard")));
        assert!(matches!(&f.body[1], Stmt::Call { .. }));
        assert!(matches!(&f.body[2], Stmt::Comment(s) if s == "stack-canary check"));
        assert!(matches!(&f.body[3], Stmt::Return { .. }));
    }

    #[test]
    fn exit_check_without_save_comment_is_untouched() {
        // Without a preceding `save guard` comment, the reload + if-goto
        // pair must NOT collapse — it could be unrelated code.
        use crate::ir::types::VReg;
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Reg(VReg::phys("stack_0")),
                },
                Stmt::If {
                    cond: Expr::Reg(VReg::Flag(crate::ir::types::Flag::Z)),
                    then_body: vec![Stmt::Goto { target: 0x100 }],
                    else_body: None,
                },
                Stmt::Return { value: None },
            ],
        };
        let orig = f.clone();
        collapse_canary_save(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn non_matching_canary_store_is_untouched() {
        // `%rax = __stack_chk_guard;` followed by a store to a *different*
        // register's value must NOT collapse.
        use crate::ir::types::VReg;
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("rax"),
                    src: Expr::Deref {
                        addr: Box::new(lea_abs(0x28)),
                        size: 8,
                    },
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("stack_0")),
                    src: Expr::Reg(VReg::phys("rbx")),
                },
            ],
        };
        recognise_canary(&mut f);
        collapse_canary_save(&mut f);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(&f.body[0], Stmt::Assign { .. }));
        assert!(matches!(&f.body[1], Stmt::Store { .. }));
    }

    #[test]
    fn canary_in_xor_cmp_also_renamed() {
        // Epilogue: rcx ^ *(u64)&[0x28]  →  rcx ^ __stack_chk_guard
        use crate::ir::types::BinOp;
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("rcx"),
                src: Expr::Bin {
                    op: BinOp::Xor,
                    lhs: Box::new(Expr::Reg(VReg::phys("rcx"))),
                    rhs: Box::new(Expr::Deref {
                        addr: Box::new(lea_abs(0x28)),
                        size: 8,
                    }),
                },
            }],
        };
        recognise_canary(&mut f);
        if let Stmt::Assign {
            src: Expr::Bin { rhs, .. },
            ..
        } = &f.body[0]
        {
            assert_eq!(
                **rhs,
                Expr::Named {
                    va: 0x28,
                    name: "__stack_chk_guard".to_string(),
                }
            );
        } else {
            panic!("unexpected shape: {:?}", f.body[0]);
        }
    }
}
