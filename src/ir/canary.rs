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

/// The TLS slots `-fstack-protector` reads the guard from, as
/// `(segment, displacement)`.
///
/// glibc puts the canary at a fixed offset in `tcbhead_t`, and that offset is
/// per-ABI: x86-64 reads `fs:0x28`, 32-bit x86 reads `gs:0x14`. Both are load-
/// bearing here — an unrecognised `gs:0x14` renders as a dereference of the
/// literal address 0x14, which faults the moment the recovered C is executed,
/// so every i386 fixture built with the distribution's default
/// `-fstack-protector-strong` crashed rather than merely reading oddly.
///
/// The SEGMENT is part of the key, not just the displacement. Win32's TIB has
/// unrelated fields low in `fs:`, and pairing the two keeps this to the two
/// shapes glibc actually emits.
const CANARY_TLS_SLOTS: &[(&str, i64)] = &[("fs", CANARY_DISP), ("gs", CANARY_DISP), ("gs", 0x14)];

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
const KNOWN_TLS_OFFSETS: &[(i64, &str)] = &[(0x00, "__tls_self"), (0x30, "__pointer_chk_guard")];

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
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collapse_exit_check(body, slot)
            }
            Stmt::For { body, .. } => collapse_exit_check(body, slot),
            _ => {}
        }
    }

    let mut i = 0;
    while i < body.len() {
        // A fully structured failure edge no longer has a goto for the older
        // reload/branch matcher below to see:
        //
        //   if (saved_guard != original_guard) { __stack_chk_fail(); }
        //
        // The prologue comment has already proved `slot` is guard storage, so
        // the exact inequality plus exact noreturn call is sufficient even if
        // late copy folding reduced the original guard load back to its GOT VA.
        let structured_failure = matches!(
            &body[i],
            Stmt::If {
                cond: cond @ Expr::Cmp {
                    op: crate::ir::types::CmpOp::Ne,
                    ..
                },
                then_body,
                else_body: None,
            } if then_body.len() == 1
                && is_stack_chk_fail_call(&then_body[0])
                && expr_mentions_slot(cond, slot)
        );
        if structured_failure {
            body[i] = Stmt::Comment("stack-canary check".to_string());
            i += 1;
            continue;
        }

        // After control-flow structuring, AArch64 commonly has the inverse
        // shape of the branch-to-failure idiom below:
        //
        //   if (saved_guard == __stack_chk_guard) { ...; return value; }
        //   __stack_chk_fail();
        //
        // The success edge has become an inline arm, while the fallthrough is
        // the noreturn failure call. Once the matching prologue save has proved
        // `slot` is canary storage, retain the success body and discard only the
        // compiler-inserted guard machinery.
        let structured_success = if i + 1 < body.len() && is_stack_chk_fail_call(&body[i + 1]) {
            match &body[i] {
                Stmt::If {
                    cond:
                        cond @ Expr::Cmp {
                            op: crate::ir::types::CmpOp::Eq,
                            ..
                        },
                    then_body,
                    else_body: None,
                } if !then_body.is_empty()
                    && matches!(then_body.last(), Some(Stmt::Return { .. }))
                    && expr_mentions_slot(cond, slot)
                    && expr_mentions_guard(cond) =>
                {
                    Some(then_body.clone())
                }
                _ => None,
            }
        } else {
            None
        };
        if let Some(success_body) = structured_success {
            body.splice(
                i..=i + 1,
                std::iter::once(Stmt::Comment("stack-canary check".to_string()))
                    .chain(success_body),
            );
            i += 1;
            continue;
        }

        // After stack-local promotion and flag folding GCC's reload/xor/jne
        // sequence can already be one direct comparison of the saved slot
        // against the recovered TLS displacement. The preceding save comment
        // supplies the provenance that makes this otherwise broad-looking
        // constant comparison safe to erase.
        let is_direct_check = matches!(
            &body[i],
            Stmt::If {
                cond,
                then_body,
                else_body: None,
            } if then_body.len() == 1
                && matches!(&then_body[0], Stmt::Goto { .. })
                && expr_mentions_slot(cond, slot)
                && expr_mentions_canary_marker(cond)
        );
        if is_direct_check {
            body[i] = Stmt::Comment("stack-canary check".to_string());
            i += 1;
            continue;
        }

        if i + 1 >= body.len() {
            break;
        }

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

fn is_stack_chk_fail_call(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Call {
            target: Expr::Named { name, .. },
            ..
        } if name.split('@').next() == Some("__stack_chk_fail")
    )
}

fn expr_mentions_slot(e: &Expr, slot: &str) -> bool {
    match e {
        Expr::Reg(crate::ir::types::VReg::Phys(name)) => name == slot,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_mentions_slot(lhs, slot) || expr_mentions_slot(rhs, slot)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expr_mentions_slot(cond, slot)
                || expr_mentions_slot(if_true, slot)
                || expr_mentions_slot(if_false, slot)
        }
        Expr::Un { src, .. } => expr_mentions_slot(src, slot),
        Expr::Cast { expr, .. } => expr_mentions_slot(expr, slot),
        Expr::Deref { addr, .. } => expr_mentions_slot(addr, slot),
        Expr::FunctionTableEntry { index, .. } => expr_mentions_slot(index, slot),
        Expr::WideArithmetic { args, .. } => args.iter().any(|arg| expr_mentions_slot(arg, slot)),
        _ => false,
    }
}

fn expr_mentions_canary_marker(e: &Expr) -> bool {
    // Any of the per-ABI guard displacements, not just x86-64's `0x28` — the
    // caller has already proved the expression mentions the canary save slot,
    // which is what keeps this otherwise broad constant match safe.
    if matches!(e, Expr::Const(c) if CANARY_TLS_SLOTS.iter().any(|(_, off)| off == c))
        || expr_mentions_guard(e)
    {
        return true;
    }
    match e {
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_mentions_canary_marker(lhs) || expr_mentions_canary_marker(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expr_mentions_canary_marker(cond)
                || expr_mentions_canary_marker(if_true)
                || expr_mentions_canary_marker(if_false)
        }
        Expr::Un { src, .. } => expr_mentions_canary_marker(src),
        Expr::Cast { expr, .. } => expr_mentions_canary_marker(expr),
        Expr::Deref { addr, .. } => expr_mentions_canary_marker(addr),
        Expr::FunctionTableEntry { index, .. } => expr_mentions_canary_marker(index),
        Expr::WideArithmetic { args, .. } => args.iter().any(expr_mentions_canary_marker),
        _ => false,
    }
}

fn expr_mentions_guard(e: &Expr) -> bool {
    match e {
        Expr::Named { name, .. } => name == CANARY_NAME,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_mentions_guard(lhs) || expr_mentions_guard(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expr_mentions_guard(cond)
                || expr_mentions_guard(if_true)
                || expr_mentions_guard(if_false)
        }
        Expr::Un { src, .. } => expr_mentions_guard(src),
        Expr::Cast { expr, .. } => expr_mentions_guard(expr),
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
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => collapse_body(body),
            Stmt::For { body, .. } => collapse_body(body),
            _ => {}
        }
    }

    let mut i = 0;
    while i + 1 < body.len() {
        // AArch64's guard is reached through a GOT entry. After constant and
        // copy folding the two load instructions commonly become:
        //
        //   %addr = *(u64)__stack_chk_guard;
        //   store %stack_N = *(u64)&%addr;
        //
        // This is the split-statement counterpart of `got_indirect_guard`.
        // The relocation name, two 64-bit dereferences, and stack destination
        // keep the match specific to the ABI canary sequence.
        let got_addr = match &body[i] {
            Stmt::Assign {
                dst,
                src:
                    Expr::Deref {
                        addr: named_slot,
                        size: 8,
                    },
            } if matches!(
                named_slot.as_ref(),
                Expr::Named { name, .. } if canary_symbol(name)
            ) =>
            {
                Some(dst.clone())
            }
            _ => None,
        };
        let split_got_store = got_addr.as_ref().and_then(|got_addr| {
            let mut j = i + 1;
            while j < body.len() {
                let slot = match &body[j] {
                    Stmt::Store {
                        addr: Expr::Reg(crate::ir::types::VReg::Phys(slot)),
                        src:
                            Expr::Deref {
                                addr: saved_addr,
                                size: 8,
                            },
                        size: 8,
                    } if slot.starts_with("stack_")
                        && is_identity_address(saved_addr, got_addr) =>
                    {
                        Some(slot.clone())
                    }
                    _ => None,
                };
                if let Some(slot) = slot {
                    return Some((j, slot));
                }

                // Scan only a straight-line prologue and stop at any other use
                // or redefinition. Frame saves and unrelated initializers may
                // legally sit between the two AArch64 loads.
                if crate::ir::dead_stores::stmt_reads(&body[j], got_addr)
                    || stmt_overwrites(&body[j], got_addr)
                    || !matches!(
                        &body[j],
                        Stmt::Assign { .. }
                            | Stmt::Store { .. }
                            | Stmt::Comment(_)
                            | Stmt::Label(_)
                            | Stmt::Nop
                    )
                {
                    return None;
                }
                j += 1;
            }
            None
        });
        if let Some((store_index, slot)) = split_got_store {
            body.remove(store_index);
            body[i] = Stmt::Comment(format!("stack canary: save guard to %{}", slot));
            i += 1;
            continue;
        }

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
                ..
            } if slot.starts_with("stack_") && src == &load_dst => Some(slot.clone()),
            _ => None,
        };
        if let Some(slot) = store_match {
            body.remove(i + 1);
            body[i] = Stmt::Comment(format!("stack canary: save guard to %{}", slot));
        }
        i += 1;
    }
}

fn is_identity_address(expr: &Expr, target: &crate::ir::types::VReg) -> bool {
    match expr {
        Expr::Reg(register) => register == target,
        Expr::Lea {
            base: Some(base),
            index: None,
            scale: 0,
            disp: 0,
            segment: None,
        } => base == target,
        _ => false,
    }
}

fn stmt_overwrites(stmt: &Stmt, target: &crate::ir::types::VReg) -> bool {
    match stmt {
        Stmt::Assign { dst, .. } => dst == target,
        Stmt::Call { dst, .. } => dst.as_ref() == Some(target),
        Stmt::Pop { target: dst } => dst == target,
        _ => false,
    }
}

fn rewrite_body(body: &mut [Stmt]) {
    for s in body.iter_mut() {
        match s {
            Stmt::IndirectGoto { target } => rewrite_expr(target),
            Stmt::Assign { src, .. } => rewrite_expr(src),
            Stmt::Store { addr, src, .. } => {
                rewrite_expr(addr);
                rewrite_expr(src);
            }
            Stmt::Call { target, args, .. } => {
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
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                rewrite_body(std::slice::from_mut(init.as_mut()));
                rewrite_expr(cond);
                rewrite_body(body);
                rewrite_body(std::slice::from_mut(step.as_mut()));
            }
            Stmt::DoWhile { body, cond } => {
                rewrite_body(body);
                rewrite_expr(cond);
            }
            Stmt::Push { value } => rewrite_expr(value),
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
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
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {}
        }
    }
}

/// The AArch64 shape: a load of the guard *through its GOT entry*.
///
/// There is no TLS segment override to key on. `gcc -fstack-protector` emits
///
/// ```text
///   adrp x0, <got page>
///   ldr  x0, [x0, #:got_lo12:__stack_chk_guard]   ; the guard's ADDRESS
///   ldr  x1, [x0]                                 ; the guard's VALUE
/// ```
///
/// so the AST is a dereference of a dereference of the GOT slot. The slot is
/// named by an `R_AARCH64_GLOB_DAT` relocation that `analysis::elf_got` already
/// resolves and `name_resolve` has already applied by the time this runs, so the
/// match is on that *name* — never on the shape alone.
///
/// Leaving it unrecognised is not cosmetic. The renderer replaces an
/// original-image address with a portable zero-filled object, so the recovered C
/// dereferenced a null pointer: every `-fstack-protector` function with a local
/// array took SIGSEGV when recompiled and run.
fn got_indirect_guard(addr: &Expr) -> Option<(u64, &'static str)> {
    let Expr::Deref { addr: slot, .. } = addr else {
        return None;
    };
    match slot.as_ref() {
        Expr::Named { va, name } if canary_symbol(name) => Some((*va, CANARY_NAME)),
        _ => None,
    }
}

/// Is this the guard symbol, allowing for a version suffix (`@GLIBC_2.17`)?
fn canary_symbol(name: &str) -> bool {
    name.split('@').next() == Some(CANARY_NAME)
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
            if let Some((va, name)) = got_indirect_guard(addr) {
                *e = Expr::Named {
                    va,
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
        Expr::Call { target, args, .. } => {
            rewrite_expr(target);
            args.iter_mut().for_each(rewrite_expr);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            rewrite_expr(cond);
            rewrite_expr(if_true);
            rewrite_expr(if_false);
        }
        Expr::Un { src, .. } => rewrite_expr(src),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => rewrite_expr(expr),
        Expr::FunctionTableEntry { index, .. } => rewrite_expr(index),
        Expr::WideArithmetic { args, .. } => args.iter_mut().for_each(rewrite_expr),
        Expr::Reg(_)
        | Expr::FloatConst { .. }
        | Expr::StackAddr { .. }
        | Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
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
        if CANARY_TLS_SLOTS
            .iter()
            .any(|(seg, off)| segment.as_deref() == Some(*seg) && disp == off)
        {
            return Some((*disp, CANARY_NAME));
        }
        for (off, name) in KNOWN_TLS_OFFSETS {
            if *disp == *off {
                return Some((*off, *name));
            }
        }
    }
    None
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

    /// AArch64 reaches the guard through its GOT entry rather than through a
    /// TLS segment override. Left unrecognised, the renderer substitutes a
    /// portable zero-filled object for the original-image address and the
    /// recovered C dereferences a null pointer.
    #[test]
    fn aarch64_got_indirect_canary_load_is_renamed() {
        let guard_slot = Expr::Named {
            va: 0x1ffd8,
            name: "__stack_chk_guard".into(),
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("x1"),
                src: Expr::Deref {
                    addr: Box::new(Expr::Deref {
                        addr: Box::new(guard_slot),
                        size: 8,
                    }),
                    size: 8,
                },
            }],
        };
        recognise_canary(&mut f);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("statement shape changed");
        };
        assert_eq!(
            *src,
            Expr::Named {
                va: 0x1ffd8,
                name: "__stack_chk_guard".into()
            },
            "the GOT-indirect guard load was not recognised: {src:?}"
        );
    }

    /// The match is on the relocation's SYMBOL, never on the double-deref shape
    /// alone — an indirect load through any other GOT entry is ordinary code.
    #[test]
    fn a_got_indirect_load_of_another_symbol_is_left_alone() {
        let other = Expr::Deref {
            addr: Box::new(Expr::Deref {
                addr: Box::new(Expr::Named {
                    va: 0x1ffe0,
                    name: "stdout".into(),
                }),
                size: 8,
            }),
            size: 8,
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("x1"),
                src: other.clone(),
            }],
        };
        recognise_canary(&mut f);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("statement shape changed");
        };
        assert_eq!(*src, other, "an unrelated GOT load was rewritten");
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

    /// glibc's 32-bit x86 `tcbhead_t` puts the guard at `gs:0x14`. Unrecognised,
    /// it renders as a dereference of the literal address 0x14 and faults.
    #[test]
    fn i386_canary_load_at_gs_0x14_is_renamed() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("eax"),
                src: Expr::Deref {
                    addr: Box::new(lea_abs_seg(0x14, Some("gs".to_string()))),
                    size: 4,
                },
            }],
        };
        recognise_canary(&mut f);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("statement shape changed");
        };
        assert_eq!(
            *src,
            Expr::Named {
                va: 0x14,
                name: "__stack_chk_guard".to_string(),
            }
        );
    }

    /// The segment is part of the key. Win32's TIB has unrelated fields low in
    /// `fs:`, and glibc never reads the guard through `fs:` on 32-bit x86.
    #[test]
    fn fs_0x14_is_not_the_canary() {
        let original = Expr::Deref {
            addr: Box::new(lea_abs_seg(0x14, Some("fs".to_string()))),
            size: 4,
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("eax"),
                src: original.clone(),
            }],
        };
        recognise_canary(&mut f);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("statement shape changed");
        };
        assert_eq!(*src, original);
    }

    /// An absolute load from 0x14 with no segment override is ordinary memory.
    #[test]
    fn unsegmented_0x14_is_not_the_canary() {
        let original = Expr::Deref {
            addr: Box::new(lea_abs_seg(0x14, None)),
            size: 4,
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: VReg::phys("eax"),
                src: original.clone(),
            }],
        };
        recognise_canary(&mut f);
        let Stmt::Assign { src, .. } = &f.body[0] else {
            panic!("statement shape changed");
        };
        assert_eq!(*src, original);
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
                    size: 8,
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
                    dst: None,
                    call_spec: None,
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
    fn directly_promoted_canary_comparison_collapses_with_its_save() {
        use crate::ir::types::{CmpOp, VReg};
        let mut f = Function {
            name: "main".into(),
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
                    src: Expr::Reg(VReg::phys("rax")),
                    size: 8,
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ne,
                        lhs: Box::new(Expr::Reg(VReg::phys("stack_0"))),
                        rhs: Box::new(Expr::Const(CANARY_DISP)),
                    },
                    then_body: vec![Stmt::Goto { target: 0x1227 }],
                    else_body: None,
                },
                Stmt::Return {
                    value: Some(Expr::Const(7)),
                },
            ],
        };

        recognise_canary(&mut f);
        collapse_canary_save(&mut f);

        assert_eq!(f.body.len(), 3, "got: {:?}", f.body);
        assert!(matches!(&f.body[0], Stmt::Comment(s) if s.contains("save guard")));
        assert!(matches!(&f.body[1], Stmt::Comment(s) if s == "stack-canary check"));
        assert!(matches!(&f.body[2], Stmt::Return { .. }));
    }

    /// Constant folding can leave AArch64's GOT-indirect guard save split
    /// across one address load and the stack-slot store. Structuring then
    /// turns the success edge into an inline return followed by the noreturn
    /// failure call. The whole compiler artifact must disappear together.
    #[test]
    fn structured_aarch64_got_canary_epilogue_collapses_with_its_save() {
        use crate::ir::types::{CmpOp, VReg};
        let guard = Expr::Named {
            va: 0x1ffd8,
            name: "__stack_chk_guard".into(),
        };
        let mut f = Function {
            name: "graph_bfs".into(),
            entry_va: 0x6a0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::Deref {
                        addr: Box::new(guard.clone()),
                        size: 8,
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("var3"),
                    src: Expr::Const(0),
                },
                Stmt::Store {
                    addr: Expr::Reg(VReg::phys("stack_4")),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(VReg::phys("var1")),
                            index: None,
                            scale: 0,
                            disp: 0,
                            segment: None,
                        }),
                        size: 8,
                    },
                    size: 8,
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(VReg::phys("stack_4"))),
                        rhs: Box::new(guard),
                    },
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Const(4)),
                    }],
                    else_body: None,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x570,
                        name: "__stack_chk_fail@plt".into(),
                    },
                    args: vec![],
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        collapse_canary_save(&mut f);

        assert_eq!(f.body.len(), 4, "got: {:?}", f.body);
        assert!(matches!(&f.body[0], Stmt::Comment(s) if s.contains("save guard")));
        assert!(
            matches!(&f.body[1], Stmt::Assign { dst, src: Expr::Const(0) } if dst == &VReg::phys("var3"))
        );
        assert!(matches!(&f.body[2], Stmt::Comment(s) if s == "stack-canary check"));
        assert!(matches!(
            &f.body[3],
            Stmt::Return {
                value: Some(Expr::Const(4))
            }
        ));
    }

    #[test]
    fn structured_guard_comparison_before_an_ordinary_call_is_untouched() {
        use crate::ir::types::{CmpOp, VReg};
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Comment("stack canary: save guard to %stack_0".to_string()),
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(VReg::phys("stack_0"))),
                        rhs: Box::new(Expr::Named {
                            va: 0x1ffd8,
                            name: "__stack_chk_guard".into(),
                        }),
                    },
                    then_body: vec![Stmt::Return { value: None }],
                    else_body: None,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x600,
                        name: "ordinary_call".into(),
                    },
                    args: vec![],
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        let original = f.clone();

        collapse_canary_save(&mut f);

        assert_eq!(f, original);
    }

    #[test]
    fn structured_aarch64_failure_arm_collapses_with_a_proven_save() {
        use crate::ir::types::{CmpOp, VReg};
        let mut f = Function {
            name: "bst_inorder_checksum".into(),
            entry_va: 0x724,
            body: vec![
                Stmt::Comment("stack canary: save guard to %stack_3".to_string()),
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ne,
                        lhs: Box::new(Expr::Reg(VReg::phys("stack_3"))),
                        rhs: Box::new(Expr::Const(0x1ffd8)),
                    },
                    then_body: vec![Stmt::Call {
                        target: Expr::Named {
                            va: 0x5a0,
                            name: "__stack_chk_fail@plt".into(),
                        },
                        args: vec![],
                        dst: None,
                        call_spec: None,
                    }],
                    else_body: None,
                },
                Stmt::Return {
                    value: Some(Expr::Const(0)),
                },
            ],
        };

        collapse_canary_save(&mut f);

        assert_eq!(f.body.len(), 3, "got: {:?}", f.body);
        assert!(matches!(&f.body[1], Stmt::Comment(s) if s == "stack-canary check"));
        assert!(matches!(&f.body[2], Stmt::Return { .. }));
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
                    size: 8,
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
