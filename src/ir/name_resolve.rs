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
use std::path::Path;

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
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                resolve_expr(discriminant, addr_map);
                for (_, body) in cases.iter_mut() {
                    resolve_body(body, addr_map);
                }
                if let Some(b) = default {
                    resolve_body(b, addr_map);
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
        Expr::Lea {
            base: None,
            index: None,
            disp,
            segment: None,
            ..
        } if *disp >= 0 => {
            if let Some(name) = addr_map.get(&(*disp as u64)) {
                *e = Expr::Named {
                    va: *disp as u64,
                    name: name.clone(),
                };
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            resolve_expr(lhs, addr_map);
            resolve_expr(rhs, addr_map);
        }
        Expr::Un { src, .. } => resolve_expr(src, addr_map),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
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
    // PE exports. The object crate does not expose PE exports through
    // dynamic_symbols(), so recover the export table directly for Windows
    // decompile output.
    collect_pe_exports(data, &mut out);
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
    // PE import thunks: local executable stubs that jump through the IAT.
    for (va, name) in crate::analysis::pe_iat::pe_import_thunk_map(data) {
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

/// Helper: build an address map and optionally overlay PE/PDB public
/// function symbols from a local Microsoft-style symbol cache. Export/IAT
/// names stay preferred for exact-address collisions because they are the
/// names the binary exposes at runtime.
pub fn collect_address_map_with_pdb_cache(
    data: &[u8],
    path: &str,
    pdb_cache: Option<&Path>,
) -> HashMap<u64, String> {
    let mut out = collect_address_map(data, path);
    if let Some(cache_dir) = pdb_cache {
        collect_pe_pdb_publics(path, cache_dir, &mut out);
    }
    out
}

/// Add the current CFG discovery result as a fallback call-target map.
///
/// Import, export, symbol, and PDB names are stronger and should already
/// occupy exact-address entries in `out`. This helper only fills otherwise
/// anonymous local function entries so stripped Windows decompile output can
/// say `sub_180012340()` instead of `0x180012340()`.
pub fn add_discovered_function_names(
    out: &mut HashMap<u64, String>,
    funcs: &[crate::core::function::Function],
) -> usize {
    let mut added = 0usize;
    for func in funcs {
        let va = func.entry_point.value;
        if va == 0 || func.name.is_empty() {
            continue;
        }
        if let std::collections::hash_map::Entry::Vacant(slot) = out.entry(va) {
            slot.insert(func.name.clone());
            added += 1;
        }
    }
    added
}

fn collect_pe_exports(data: &[u8], out: &mut HashMap<u64, String>) {
    let Ok(parser) = crate::formats::pe::PeParser::new(data) else {
        return;
    };
    let image_base = parser.image_base();
    let Ok(exports) = parser.exports() else {
        return;
    };
    for export in &exports.exports {
        if export.forwarder.is_some() {
            continue;
        }
        let Some(name) = export.name else {
            continue;
        };
        if name.is_empty() || export.rva == 0 {
            continue;
        }
        out.entry(image_base + u64::from(export.rva))
            .or_insert_with(|| name.to_string());
    }
}

fn collect_pe_pdb_publics(path: &str, cache_dir: &Path, out: &mut HashMap<u64, String>) {
    if path.is_empty() || !cache_dir.is_dir() {
        return;
    }
    let Ok(Some(source)) = crate::symbols::pdb::PdbIngestor::from_pe_cache(path, cache_dir) else {
        return;
    };
    let Ok(symbols) = source.public_symbols() else {
        return;
    };
    for symbol in symbols {
        if !(symbol.code || symbol.function) || symbol.name.is_empty() {
            continue;
        }
        if let Some(va) = symbol.va {
            out.entry(va).or_insert(symbol.name);
        }
    }
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
        assert!(text.contains("call __libc_start_main@plt"), "got: {}", text);
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
    fn absolute_memory_deref_addr_gets_named() {
        let lf = mk_single_block(vec![
            Op::Load {
                dst: VReg::phys("rax"),
                addr: crate::ir::types::MemOp::plain(None, None, 1, 0x2008, 8),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        let mut map = HashMap::new();
        map.insert(0x2008, "ReadFile".to_string());
        resolve_names(&mut f, &map);
        let text = render(&f);
        assert!(text.contains("*(u64)ReadFile"), "got: {}", text);
        assert!(!text.contains("0x2008"), "raw IAT VA leaked: {}", text);
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

    #[test]
    fn collect_address_map_includes_pe_exports_on_real_binary() {
        let path = std::path::Path::new("tests/fixtures/msvc-pdb/ntdll.dll");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let map = collect_address_map(&data, path.to_str().unwrap_or(""));
        assert_eq!(
            map.get(&0x180037800).map(String::as_str),
            Some("RtlAcquireSRWLockExclusive")
        );
    }

    #[test]
    fn collect_address_map_includes_pe_import_thunks_on_real_binary() {
        let path = std::path::Path::new(
            "samples/binaries/platforms/windows/i386/export/windows/x86_64/O0/hello-c-mingw64-O0.exe",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let thunks = crate::analysis::pe_iat::pe_import_thunk_map(&data);
        let Some((thunk_va, import_name)) = thunks
            .iter()
            .find(|(_, name)| name.as_str() == "malloc" || name.as_str() == "LeaveCriticalSection")
        else {
            panic!("no PE import thunk alias found");
        };
        let map = collect_address_map(&data, path.to_str().unwrap_or(""));
        assert!(
            map.get(thunk_va).map(String::as_str) == Some(import_name.as_str()),
            "PE import thunk alias did not survive resolved map (size={})",
            map.len()
        );
    }

    #[test]
    fn pe_import_thunk_direct_call_gets_named() {
        let path = std::path::Path::new(
            "samples/binaries/platforms/windows/i386/export/windows/x86_64/O0/hello-c-mingw64-O0.exe",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let thunks = crate::analysis::pe_iat::pe_import_thunk_map(&data);
        let Some((thunk_va, import_name)) = thunks
            .iter()
            .find(|(_, name)| name.as_str() == "malloc" || name.as_str() == "LeaveCriticalSection")
        else {
            panic!("no PE import thunk alias found");
        };
        let map = collect_address_map(&data, path.to_str().unwrap_or(""));
        let lf = mk_single_block(vec![
            Op::Call {
                target: crate::ir::types::CallTarget::Direct(*thunk_va),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let r = recover(&lf, &ssa);
        let mut f = lower(&lf, &r, "f");
        resolve_names(&mut f, &map);
        let text = render(&f);
        assert!(text.contains(&format!("call {import_name}")), "got: {text}");
        assert!(
            !text.contains(&format!("call 0x{thunk_va:x}")),
            "raw thunk VA leaked: {text}"
        );
    }

    #[test]
    fn discovered_function_names_fill_only_missing_addresses() {
        let entry = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            0x401000,
            64,
            None,
            None,
        )
        .unwrap();
        let func = crate::core::function::Function::new(
            "sub_401000".to_string(),
            entry,
            crate::core::function::FunctionKind::Normal,
        )
        .unwrap();
        let imported_entry = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            0x402000,
            64,
            None,
            None,
        )
        .unwrap();
        let imported_func = crate::core::function::Function::new(
            "sub_402000".to_string(),
            imported_entry,
            crate::core::function::FunctionKind::Normal,
        )
        .unwrap();
        let mut map = HashMap::from([(0x402000, "ReadFile".to_string())]);

        let added = add_discovered_function_names(&mut map, &[func, imported_func]);

        assert_eq!(added, 1);
        assert_eq!(map.get(&0x401000).map(String::as_str), Some("sub_401000"));
        assert_eq!(map.get(&0x402000).map(String::as_str), Some("ReadFile"));
    }

    #[test]
    fn collect_address_map_can_include_pe_pdb_publics() {
        let path = std::path::Path::new("tests/fixtures/msvc-pdb/ntoskrnl.exe");
        let cache = std::path::Path::new("tests/fixtures/msvc-pdb");
        if !path.exists() || !cache.join("ntkrnlmp.pdb").exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let map =
            collect_address_map_with_pdb_cache(&data, path.to_str().unwrap_or(""), Some(cache));
        assert_eq!(
            map.get(&0x140323480).map(String::as_str),
            Some("KeReleaseSpinLock")
        );
        assert_eq!(
            map.get(&0x140a92840).map(String::as_str),
            Some("KiInitializeKernelShadowStacks")
        );
    }
}
