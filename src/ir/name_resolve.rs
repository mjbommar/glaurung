//! Replace bare `Expr::Addr(v)` VAs in a lowered [`Function`] with named
//! references when a symbol / PLT / IAT / Mach-O-stub entry is known.
//!
//! v1 scope:
//!
//! * Scans every `Stmt::Call { target: Expr::Addr(v) }` and rewrites to
//!   `Expr::Named { va: v, name }` when the VA resolves.
//! * Scans every `Stmt::Goto { target: v }` and leaves it alone — goto
//!   labels are local to the function and already render as `L_<va>`.
//! * Optionally rewrites `Expr::Addr(v)` appearing in `Stmt::Assign`'s RHS
//!   (e.g. a lifted `lea rax, [rip+X]`) when the pointed-to VA falls inside
//!   a known readable-data section — surfaced as `Expr::Named { va: v, name: "&data_name" }`.
//!   A later pass can upgrade this to a proper string literal or struct
//!   reference.

use std::collections::HashMap;

use crate::ir::ast::{Expr, Function, Stmt};

/// Apply name resolution to every `Addr` expression in `f`'s body in place.
/// Only VAs present in `addr_map` are rewritten; unknown VAs stay as
/// numeric `Expr::Addr`.
pub fn resolve_names(f: &mut Function, addr_map: &HashMap<u64, String>) {
    resolve_body(&mut f.body, addr_map);
}

fn resolve_body(body: &mut [Stmt], addr_map: &HashMap<u64, String>) {
    for s in body.iter_mut() {
        match s {
            Stmt::Assign { src, .. } => resolve_expr(src, addr_map),
            Stmt::Store { addr, src } => {
                resolve_expr(addr, addr_map);
                resolve_expr(src, addr_map);
            }
            Stmt::Call { target, args } => {
                resolve_expr(target, addr_map);
                for a in args {
                    resolve_expr(a, addr_map);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    resolve_expr(e, addr_map);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                resolve_expr(cond, addr_map);
                resolve_body(then_body, addr_map);
                if let Some(eb) = else_body {
                    resolve_body(eb, addr_map);
                }
            }
            Stmt::While { cond, body } => {
                resolve_expr(cond, addr_map);
                resolve_body(body, addr_map);
            }
            Stmt::Push { value } => resolve_expr(value, addr_map),
            Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
}

fn resolve_expr(e: &mut Expr, addr_map: &HashMap<u64, String>) {
    match e {
        Expr::Addr(a) => {
            if let Some(name) = addr_map.get(a) {
                *e = Expr::Named {
                    va: *a,
                    name: name.clone(),
                };
            }
        }
        Expr::Deref { addr, .. } => resolve_expr(addr, addr_map),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            resolve_expr(lhs, addr_map);
            resolve_expr(rhs, addr_map);
        }
        Expr::Un { src, .. } => resolve_expr(src, addr_map),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::Lea { .. }
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
    }
}

/// Helper: build a unified address map for a binary from ELF PLT, PE IAT,
/// Mach-O stubs, ELF GOT, and the defined-symbol address map. Later sources
/// overwrite earlier ones so — for example — a PLT entry hides a less
/// specific GOT name at the same address.
pub fn collect_address_map(data: &[u8], path: &str) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    // Defined symbols (functions + exported vars).
    if let Ok(obj) = object::read::File::parse(data) {
        use object::{Object, ObjectSymbol};
        for sym in obj.symbols() {
            if sym.is_definition() {
                if let (Ok(name), addr) = (sym.name(), sym.address()) {
                    if !name.is_empty() && addr != 0 {
                        out.entry(addr).or_insert_with(|| name.to_string());
                    }
                }
            }
        }
        for sym in obj.dynamic_symbols() {
            if sym.is_definition() {
                if let (Ok(name), addr) = (sym.name(), sym.address()) {
                    if !name.is_empty() && addr != 0 {
                        out.entry(addr).or_insert_with(|| name.to_string());
                    }
                }
            }
        }
    }
    // ELF GOT (may name something the symbol table doesn't).
    for (va, name) in crate::analysis::elf_got::elf_got_map(data) {
        out.insert(va, name);
    }
    // ELF PLT.
    for (va, name) in crate::analysis::elf_plt::elf_plt_map(data) {
        out.insert(va, name);
    }
    // PE IAT.
    for (va, name) in crate::analysis::pe_iat::pe_iat_map(data) {
        out.insert(va, name);
    }
    // Mach-O stubs / lazy / non-lazy pointers.
    for (va, name) in crate::analysis::macho_stubs::macho_stubs_map(data) {
        out.insert(va, name);
    }
    // Keep `path` so future resolvers can hit debug info; unused today.
    let _ = path;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{lower, render};
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover;
    use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

    fn mk_single_block(ops: Vec<Op>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1100,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(j, op)| LlirInstr {
                        va: 0x1000 + (j as u64) * 4,
                        op,
                    })
                    .collect(),
                succs: vec![],
            }],
        }
    }

    #[test]
    fn call_target_addr_gets_named() {
        let lf = mk_single_block(vec![
            Op::Call {
                target: crate::ir::types::CallTarget::Direct(0x3fd8),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        let mut map = HashMap::new();
        map.insert(0x3fd8, "__libc_start_main@plt".to_string());
        resolve_names(&mut f, &map);
        let text = render(&f);
        assert!(
            text.contains("call __libc_start_main@plt"),
            "got: {}",
            text
        );
        assert!(!text.contains("call 0x3fd8"), "raw VA leaked: {}", text);
    }

    #[test]
    fn unknown_addr_stays_numeric() {
        let lf = mk_single_block(vec![
            Op::Call {
                target: crate::ir::types::CallTarget::Direct(0xdead),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        let map = HashMap::new(); // empty
        resolve_names(&mut f, &map);
        let text = render(&f);
        assert!(text.contains("call 0xdead"), "got: {}", text);
    }

    #[test]
    fn lea_style_addr_in_assign_rhs_is_named() {
        // `%rdi = 0x2008` — a lifted `lea rdi, [rip+...]` or `mov rdi, imm`
        // that addresses a rodata string. We should surface the symbol name.
        let lf = mk_single_block(vec![
            Op::Assign {
                dst: VReg::phys("rdi"),
                src: Value::Addr(0x2008),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        let mut map = HashMap::new();
        map.insert(0x2008, "hello_str".to_string());
        resolve_names(&mut f, &map);
        let text = render(&f);
        assert!(text.contains("%rdi = hello_str"), "got: {}", text);
    }

    #[test]
    fn collect_address_map_includes_plt_on_real_binary() {
        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let map = collect_address_map(&data, path.to_str().unwrap_or(""));
        // The hello binary unconditionally pulls in __libc_start_main via
        // its PLT, so at least one value must be non-empty and contain
        // "@plt".
        assert!(
            map.values().any(|n| n.contains("@plt")),
            "no @plt entries in resolved map (size={})",
            map.len()
        );
    }
}
