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
            Stmt::IndirectGoto { target } => resolve_expr(target, addr_map),
            Stmt::Assign { src, .. } => resolve_expr(src, addr_map),
            Stmt::Store { addr, src, .. } => {
                resolve_expr(addr, addr_map);
                resolve_expr(src, addr_map);
            }
            Stmt::Call { target, args, .. } => {
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
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                resolve_body(std::slice::from_mut(init.as_mut()), addr_map);
                resolve_expr(cond, addr_map);
                resolve_body(body, addr_map);
                resolve_body(std::slice::from_mut(step.as_mut()), addr_map);
            }
            Stmt::DoWhile { body, cond } => {
                resolve_body(body, addr_map);
                resolve_expr(cond, addr_map);
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
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {}
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
        Expr::Call { target, args, .. } => {
            resolve_expr(target, addr_map);
            for argument in args {
                resolve_expr(argument, addr_map);
            }
        }
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
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            resolve_expr(cond, addr_map);
            resolve_expr(if_true, addr_map);
            resolve_expr(if_false, addr_map);
        }
        Expr::Un { src, .. } => resolve_expr(src, addr_map),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => resolve_expr(expr, addr_map),
        Expr::FunctionTableEntry { index, .. } => resolve_expr(index, addr_map),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                resolve_expr(argument, addr_map);
            }
        }
        Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
    }
}

/// True when a symbol name is a compiler-internal alias or clone rather than the
/// name a reader (or a C compiler) would use.
///
/// gcc emits `fib.localalias` — a LOCAL alias so a self-call can skip the PLT —
/// at the same address as the GLOBAL `fib`, and several more suffixes for clones
/// and split-out paths. One list, because two copies is how they drift.
pub(crate) fn is_internal_alias(name: &str) -> bool {
    const INTERNAL_SUFFIXES: &[&str] = &[
        ".localalias",
        ".cold",
        ".part.",
        ".isra.",
        ".constprop.",
        ".lto_priv.",
    ];
    INTERNAL_SUFFIXES.iter().any(|s| name.contains(s))
}

/// How good a name is for an address, when several symbols share it.
///
/// gcc emits `fib.localalias` (a LOCAL alias so a self-call can skip the PLT)
/// alongside the GLOBAL `fib`, at the same address. Taking whichever the symbol
/// iteration happened to reach first made a recursive function call
/// `fib_localalias()` — a name nothing declares, so the decompiled C did not even
/// compile. Compilers emit several such internal suffixes (`.cold`, `.part.N`,
/// `.isra.N`, `.constprop.N`) for clones and split-out paths; the plain name is the
/// one a reader — and a C compiler — can use.
///
/// Higher is better: a global plain name beats a local plain name beats a global
/// internal alias beats a local internal alias.
///
/// The suffix list lives in [`is_internal_alias`] so the ranking and every other
/// consumer cannot drift apart.
fn symbol_rank(name: &str, is_global: bool) -> u8 {
    let internal = is_internal_alias(name);
    match (is_global, internal) {
        (true, false) => 3,
        (false, false) => 2,
        (true, true) => 1,
        (false, true) => 0,
    }
}

/// Helper: build a unified address map for a binary from ELF PLT, PE IAT,
/// Mach-O stubs, ELF GOT, and the defined-symbol address map. Later sources
/// overwrite earlier ones so — for example — a PLT entry hides a less
/// specific GOT name at the same address.
pub fn collect_address_map(data: &[u8], path: &str) -> HashMap<u64, String> {
    collect_address_map_and_data_symbols(data, path).0
}

/// The call-target name map AND the named-static-storage table, from ONE parse
/// of the image.
///
/// The two answer different questions -- "what callable lives here" admits any
/// defined symbol, "what object begins exactly here" admits only sized data --
/// and they are kept as separate outputs so a function name can never reach a
/// data slot. They share a parse because parsing twice is measurable: see
/// `test_object_parse_count_is_a_session_constant_not_a_function_of_the_binary`.
pub fn collect_address_map_and_data_symbols(
    data: &[u8],
    path: &str,
) -> (HashMap<u64, String>, crate::ir::data_symbols::DataSymbols) {
    let mut out = HashMap::new();
    let mut data_symbols = crate::ir::data_symbols::DataSymbols::new();
    // Defined symbols (functions + exported vars). Several symbols routinely share
    // one address, so the FIRST one seen must not simply win — see `symbol_rank`.
    if let Ok(obj) = crate::decompile::profile::parse_object(data) {
        use object::{Object, ObjectSymbol};
        let mut rank: HashMap<u64, u8> = HashMap::new();
        let mut consider =
            |addr: u64, name: &str, is_global: bool, out: &mut HashMap<u64, String>| {
                if name.is_empty() || addr == 0 {
                    return;
                }
                let r = symbol_rank(name, is_global);
                if rank.get(&addr).is_none_or(|&best| r > best) {
                    rank.insert(addr, r);
                    out.insert(addr, name.to_string());
                }
            };
        for sym in obj.symbols() {
            if sym.is_definition() {
                if let (Ok(name), addr) = (sym.name(), sym.address()) {
                    consider(addr, name, sym.is_global(), &mut out);
                }
            }
        }
        for sym in obj.dynamic_symbols() {
            if sym.is_definition() {
                if let (Ok(name), addr) = (sym.name(), sym.address()) {
                    consider(addr, name, sym.is_global(), &mut out);
                }
            }
        }
        // Named static storage, gathered from the SAME parse. It used to have
        // its own `parse_object`, which took whole-program object parses from
        // 20 to 21 and tripped the object-parse ceiling. Parsing an image
        // twice to ask it two questions is what that test exists to prevent.
        data_symbols = crate::ir::data_symbols::from_object(&obj);
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
    // MinGW CRT relationships are binary-backed names too, and must not
    // depend on whether a bounded discovery happened to retain the helper.
    for (va, name) in crate::analysis::cfg::pe_runtime_function_names(data) {
        match out.entry(va) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(name);
            }
            std::collections::hash_map::Entry::Occupied(mut slot)
                if slot.get().starts_with("sub_") || (slot.get() == "_main" && name == "main") =>
            {
                slot.insert(name);
            }
            std::collections::hash_map::Entry::Occupied(_) => {}
        }
    }
    // Mach-O stubs / lazy / non-lazy pointers.
    for (va, name) in crate::analysis::macho_stubs::macho_stubs_map(data) {
        out.insert(va, name);
    }
    // Keep `path` so future resolvers can hit debug info; unused today.
    let _ = path;
    (out, data_symbols)
}

/// Helper: build an address map and optionally overlay PE/PDB public
/// function symbols from a local Microsoft-style symbol cache. Export/IAT
/// names stay preferred for exact-address collisions because they are the
/// names the binary exposes at runtime.
/// [`collect_address_map_with_pdb_cache`] plus the named-static-storage table,
/// from one parse of the image.
pub fn collect_address_map_with_pdb_cache_and_data_symbols(
    data: &[u8],
    path: &str,
    pdb_cache: Option<&Path>,
) -> (HashMap<u64, String>, crate::ir::data_symbols::DataSymbols) {
    let (mut out, data_symbols) = collect_address_map_and_data_symbols(data, path);
    if let Some(cache_dir) = pdb_cache {
        collect_pe_pdb_publics(path, cache_dir, &mut out);
    }
    (out, data_symbols)
}

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
        match out.entry(va) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(func.name.clone());
                added += 1;
            }
            std::collections::hash_map::Entry::Occupied(mut slot)
                if slot.get().starts_with("sub_") && !func.name.starts_with("sub_") =>
            {
                slot.insert(func.name.clone());
                added += 1;
            }
            std::collections::hash_map::Entry::Occupied(_) => {}
        }
    }
    added
}

/// Overlay names an ANALYST chose, overriding every automatic source.
///
/// This is the one direction of the loop that made the KB write-only. Every
/// other populator of this map answers "what does the binary say this is
/// called" -- symbol tables, imports, exports, FLIRT, DWARF, PDB, discovery --
/// and every one of them yields to an existing entry, because they are ranked
/// against each other. An analyst's rename is not another such source. It is a
/// decision ABOUT those sources, so it is the only one that overwrites.
///
/// That is the `manual` end of the project file's `set_by` ladder
/// (manual/dwarf/stdlib/flirt/propagated/auto/borrowed), and applying it here
/// rather than at the print boundary is what makes it reach BOTH the function's
/// own name and every call site that targets it: `resolve_names` rewrites
/// `Expr::Addr` into `Expr::Named` from this same map, so one overlay renames
/// the definition and its callers together. Renaming only the definition is the
/// failure this exists to avoid -- a callgraph where `main` calls `sub_1140`
/// while `sub_1140` is displayed as `parse_packet` is harder to read than one
/// with no names at all.
///
/// An empty name is ignored rather than applied: a project row with a blank
/// canonical name is a bug in whatever wrote it, and honouring it would erase a
/// good automatic name.
///
/// # Aliases follow the rename
///
/// A call to a function in the same ELF shared object does not target the
/// function -- it targets that function's PLT stub, at a different address, and
/// the map names the stub `validate@plt`. Overriding only the definition's
/// address therefore renames the header and leaves every call site reading the
/// old name, which is precisely the split-brain output described above.
///
/// So an override also rewrites the ALIAS SPELLINGS of the name it replaced:
/// any other address whose current name is the old name plus an `@`-qualifier
/// (`@plt`, `@got`) becomes the new name with the same qualifier. The qualifier
/// is kept because it is not decoration -- it tells the analyst the call goes
/// through a stub rather than to the function body.
///
/// The comparison is against the old name at the overridden address, not
/// against the new one, and only `@`-qualified spellings are followed. A
/// different function that merely shares a name (two `static` helpers in
/// separate translation units) has no `@` qualifier and is left alone.
pub fn apply_analyst_names(
    out: &mut HashMap<u64, String>,
    overrides: &HashMap<u64, String>,
) -> Vec<(String, String)> {
    let mut applied: Vec<(String, String)> = Vec::new();
    // Collected before any write, so one override cannot see another's effect
    // and rename an alias twice.
    let mut alias_rewrites: Vec<(u64, String)> = Vec::new();
    for (va, name) in overrides {
        if *va == 0 || name.trim().is_empty() {
            continue;
        }
        if let Some(previous) = out.get(va) {
            let previous = previous.clone();
            if !previous.is_empty() && previous != *name {
                for (alias_va, alias_name) in out.iter() {
                    if *alias_va == *va {
                        continue;
                    }
                    let Some((base, qualifier)) = alias_name.split_once('@') else {
                        continue;
                    };
                    if base == previous {
                        alias_rewrites.push((*alias_va, format!("{}@{}", name.trim(), qualifier)));
                    }
                }
                applied.push((previous, name.trim().to_string()));
            }
        }
        out.insert(*va, name.trim().to_string());
    }
    for (va, name) in alias_rewrites {
        out.insert(va, name);
    }
    applied.sort();
    applied.dedup();
    applied
}

/// Add anonymous names for exact call targets referenced by discovered functions.
///
/// A bounded address-scoped analysis may preserve a tail-call boundary without
/// spending the time to discover the target function itself.  The xref is still
/// concrete callable-entry evidence, so expose the same deterministic `sub_<va>`
/// spelling that full discovery would have supplied.  Existing symbol, import,
/// export, FLIRT, DWARF, and PDB names always win.
pub fn add_referenced_function_names(
    out: &mut HashMap<u64, String>,
    funcs: &[crate::core::function::Function],
) -> usize {
    let mut added = 0usize;
    for func in funcs {
        for callee in &func.callees {
            let va = callee.value;
            if va == 0 {
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(slot) = out.entry(va) {
                slot.insert(format!("sub_{va:x}"));
                added += 1;
            }
        }
    }
    added
}

/// Give exact referenced targets a library name before the anonymous fallback.
pub fn add_flirt_referenced_function_names(
    image: &crate::program::image::ProgramImage,
    out: &mut HashMap<u64, String>,
    funcs: &[crate::core::function::Function],
) -> usize {
    let Some(library) = crate::flirt::load_default_library() else {
        return 0;
    };
    // A Function's CFG span is not an exact symbol length: unreachable literal
    // pools and split cold regions can belong to the archive symbol without
    // being reachable from its entry. Only an authoritative unwind interval is
    // strong enough to eliminate an otherwise byte-matching signature by
    // length. Absence leaves ordinary pattern/CRC matching in force.
    let lengths = image
        .eh_frame_functions()
        .iter()
        .filter_map(|range| Some((range.start, range.end.checked_sub(range.start)?)))
        .collect::<HashMap<_, _>>();
    let referenced = funcs
        .iter()
        .flat_map(|function| function.callees.iter().map(|callee| callee.value))
        .filter(|va| *va != 0)
        .collect::<std::collections::HashSet<_>>();

    let targets = referenced
        .into_iter()
        .map(|va| (va, lengths.get(&va).copied()));
    let mut added = 0;
    for (va, name) in crate::flirt::names_at_vas_with_lengths(image.bytes(), targets, &library) {
        if insert_flirt_name(out, va, name) {
            added += 1;
        }
    }
    added
}

fn insert_flirt_name(out: &mut HashMap<u64, String>, va: u64, name: String) -> bool {
    match out.entry(va) {
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(name);
            true
        }
        std::collections::hash_map::Entry::Occupied(mut slot) if slot.get().starts_with("sub_") => {
            slot.insert(name);
            true
        }
        std::collections::hash_map::Entry::Occupied(_) => false,
    }
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

/// Build a VA -> PDB public symbol map for a PE binary using a
/// Microsoft-style symbol cache. Returns an empty map when the PE has no
/// CodeView record, the cache misses, or the PDB has no public symbols.
///
/// This is the same lookup the decompile pipeline performs via
/// `collect_address_map_with_pdb_cache`, exposed standalone for callers
/// (e.g. binary_diff, future agents) that need VA -> name resolution
/// without running the full decompiler.
pub fn collect_pdb_public_symbol_map(path: &str, cache_dir: &Path) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    collect_pe_pdb_publics(path, cache_dir, &mut out);
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_flirt_name_replaces_only_an_automatic_placeholder() {
        let mut map = HashMap::from([
            (0x1000, "sub_1000".to_string()),
            (0x2000, "symbol_name".to_string()),
        ]);
        assert!(insert_flirt_name(&mut map, 0x1000, "puts".to_string()));
        assert!(!insert_flirt_name(&mut map, 0x2000, "wrong".to_string()));
        assert_eq!(map.get(&0x1000).map(String::as_str), Some("puts"));
        assert_eq!(map.get(&0x2000).map(String::as_str), Some("symbol_name"));
    }

    /// The analyst's rename must beat every automatic source, because it is a
    /// decision about them rather than another one of them.
    #[test]
    fn an_analyst_name_overrides_an_automatic_one() {
        let mut map = HashMap::from([
            (0x1140u64, "validate".to_string()), // from the symbol table
            (0x1200u64, "sub_1200".to_string()), // from discovery
        ]);
        let applied = apply_analyst_names(
            &mut map,
            &HashMap::from([(0x1140u64, "parse_packet_hdr".to_string())]),
        );
        assert_eq!(
            applied,
            vec![("validate".to_string(), "parse_packet_hdr".to_string())],
            "the old->new pair is reported so name-keyed structures can be rekeyed"
        );
        assert_eq!(
            map.get(&0x1140).map(String::as_str),
            Some("parse_packet_hdr")
        );
        assert_eq!(
            map.get(&0x1200).map(String::as_str),
            Some("sub_1200"),
            "an address the analyst did not name keeps its automatic name"
        );
    }

    /// A blank row is a bug in whatever wrote it; honouring it would erase a
    /// good automatic name and leave the function anonymous.
    #[test]
    fn a_blank_analyst_name_does_not_erase_an_automatic_one() {
        let mut map = HashMap::from([(0x1140u64, "validate".to_string())]);
        let applied = apply_analyst_names(
            &mut map,
            &HashMap::from([
                (0x1140u64, "   ".to_string()),
                (0u64, "null_entry".to_string()),
            ]),
        );
        assert!(applied.is_empty());
        assert_eq!(map.get(&0x1140).map(String::as_str), Some("validate"));
        assert!(
            !map.contains_key(&0),
            "address zero is never a function entry"
        );
    }

    /// An analyst name for an address no automatic source knew about is still
    /// applied -- discovery may have missed the function entirely.
    #[test]
    fn an_analyst_name_for_an_unknown_address_is_added() {
        let mut map: HashMap<u64, String> = HashMap::new();
        assert_eq!(
            apply_analyst_names(
                &mut map,
                &HashMap::from([(0x2000u64, "handler".to_string())])
            ),
            Vec::new(),
            "an address with no previous name has no old spelling to rekey"
        );
        assert_eq!(map.get(&0x2000).map(String::as_str), Some("handler"));
    }

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
                effects: None,
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
                effects: None,
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
                effects: None,
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
        let recovered_entry = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            0x403000,
            64,
            None,
            None,
        )
        .unwrap();
        let recovered_func = crate::core::function::Function::new(
            "__main".to_string(),
            recovered_entry,
            crate::core::function::FunctionKind::Normal,
        )
        .unwrap();
        let mut map = HashMap::from([
            (0x402000, "ReadFile".to_string()),
            (0x403000, "sub_403000".to_string()),
        ]);

        let added = add_discovered_function_names(&mut map, &[func, imported_func, recovered_func]);

        assert_eq!(added, 2);
        assert_eq!(map.get(&0x401000).map(String::as_str), Some("sub_401000"));
        assert_eq!(map.get(&0x402000).map(String::as_str), Some("ReadFile"));
        assert_eq!(map.get(&0x403000).map(String::as_str), Some("__main"));
    }

    #[test]
    fn referenced_function_names_cover_bounded_anonymous_callees() {
        let entry = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            0x401000,
            64,
            None,
            None,
        )
        .unwrap();
        let callee = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            0x405000,
            64,
            None,
            None,
        )
        .unwrap();
        let known_callee = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            0x406000,
            64,
            None,
            None,
        )
        .unwrap();
        let mut func = crate::core::function::Function::new(
            "caller".to_string(),
            entry,
            crate::core::function::FunctionKind::Normal,
        )
        .unwrap();
        func.add_callee(callee);
        func.add_callee(known_callee);
        let mut map = HashMap::from([(0x406000, "known_worker".to_string())]);

        let added = add_referenced_function_names(&mut map, &[func]);

        assert_eq!(added, 1);
        assert_eq!(map.get(&0x405000).map(String::as_str), Some("sub_405000"));
        assert_eq!(map.get(&0x406000).map(String::as_str), Some("known_worker"));
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

    #[test]
    fn symbol_rank_prefers_the_plain_name_a_caller_can_use() {
        // The exact collision that made a recursive call render `fib_localalias()`:
        // gcc emits GLOBAL `fib` and LOCAL `fib.localalias` at one address. The plain
        // global name must outrank the internal local alias regardless of iteration
        // order.
        assert!(symbol_rank("fib", true) > symbol_rank("fib.localalias", false));
        // Full ordering: global-plain > local-plain > global-internal > local-internal.
        assert!(symbol_rank("f", true) > symbol_rank("f", false));
        assert!(symbol_rank("f", false) > symbol_rank("f.cold", true));
        assert!(symbol_rank("f.cold", true) > symbol_rank("f.cold", false));
        // Every internal suffix a compiler emits for clones/split-out paths is
        // recognised as internal, so none of them can shadow the plain name.
        for internal in [
            "f.localalias",
            "f.cold",
            "f.part.0",
            "f.isra.3",
            "f.constprop.1",
            "f.lto_priv.42",
        ] {
            assert!(
                symbol_rank("f", false) > symbol_rank(internal, true),
                "plain local name must outrank the internal alias {internal}"
            );
        }
    }
}

/// Pick the best name for the outer function being decompiled.
///
/// `discovered_name` is whatever the CFG discovery pass produced
/// (`sub_<va>` for stripped binaries, a real symbol when one was available
/// at scan time). `addr_map` has been overlaid with PE/PDB public symbols
/// when a `--pdb-cache` was supplied, so this gives the PDB name priority
/// over the placeholder `sub_<va>` -- the exact scenario Phase F2 / A3
/// targets. When `discovered_name` already looks real (anything other than
/// `sub_<hex>`) we keep it so we don't trample a stronger DWARF / FLIRT /
/// IAT label that the CFG pass already applied.
pub(crate) fn resolve_outer_function_name(
    discovered_name: &str,
    func_va: u64,
    addr_map: &std::collections::HashMap<u64, String>,
) -> String {
    // The address map is already best-ranked per address (`name_resolve::symbol_rank`),
    // so it is consulted whenever the discovered name is one we would rather not use:
    // a synthesised `sub_`, OR a compiler-internal alias.
    //
    // gcc -O2 emits `fib.localalias` at the SAME address as the global `fib`, and
    // discovery can pick either. Taking the alias renamed the function
    // `fib_localalias`, which no source declares — so DecBench could not match it to
    // `fib` and scored NO graph edit distance for the whole binary, while angr scored
    // it normally. A name nobody else uses is not a cosmetic problem.
    let unwanted = discovered_name.starts_with("sub_") || is_internal_alias(discovered_name);
    if !unwanted {
        return discovered_name.to_string();
    }
    match addr_map.get(&func_va) {
        Some(name) if !name.is_empty() && !name.starts_with("sub_") && !is_internal_alias(name) => {
            name.clone()
        }
        _ => discovered_name.to_string(),
    }
}

/// `resolve_outer_function_name`, with an analyst rename able to outrank a name
/// the binary itself supplies.
///
/// `resolve_outer_function_name` answers "what does this binary call this
/// function", and correctly stops at the first *wanted* answer: a real
/// `.symtab` name beats anything in the address map, so the map is not even
/// consulted. An analyst rename is not another answer to that question -- it is
/// a decision that overrides it, the same `manual`-wins rule the project file
/// enforces on every writable fact. Handling it inside the rank logic would
/// mean teaching the ranker that one of its inputs is not a symbol source, so
/// it is a separate, explicit step instead.
///
/// The overlay is checked before the rank walk and after nothing, because a
/// rename with a lower-ranked spelling (`f` over `fib.localalias`) is still the
/// name the analyst asked for.
pub(crate) fn resolve_outer_function_name_with_analyst(
    discovered_name: &str,
    func_va: u64,
    addr_map: &std::collections::HashMap<u64, String>,
    analyst: Option<&std::collections::HashMap<u64, String>>,
) -> String {
    if let Some(names) = analyst {
        if let Some(name) = names.get(&func_va) {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    resolve_outer_function_name(discovered_name, func_va, addr_map)
}

#[cfg(test)]
mod analyst_outer_name_tests {
    use super::*;
    use std::collections::HashMap;

    /// The case the whole change exists for: a function the binary names via
    /// `.symtab`, which `resolve_outer_function_name` returns without ever
    /// consulting the map. An analyst rename must still win.
    #[test]
    fn an_analyst_rename_outranks_a_real_symtab_name() {
        let addr_map = HashMap::new();
        let analyst = HashMap::from([(0x1030u64, "parse_packet_hdr".to_string())]);
        assert_eq!(
            resolve_outer_function_name_with_analyst("validate", 0x1030, &addr_map, Some(&analyst)),
            "parse_packet_hdr"
        );
    }

    /// A rename to a name the ranker would otherwise reject is still honoured:
    /// the analyst is not asking for a ranking opinion.
    #[test]
    fn a_rename_to_a_low_ranked_spelling_is_honoured() {
        let addr_map = HashMap::from([(0x40u64, "fib".to_string())]);
        let analyst = HashMap::from([(0x40u64, "sub_step".to_string())]);
        assert_eq!(
            resolve_outer_function_name_with_analyst(
                "fib.localalias",
                0x40,
                &addr_map,
                Some(&analyst)
            ),
            "sub_step"
        );
    }

    /// No overlay, an empty overlay, a blank name, and a miss must all leave the
    /// existing ranking exactly as it was -- this is the path every caller that
    /// passes no project file takes.
    #[test]
    fn absent_or_blank_entries_change_nothing() {
        let addr_map = HashMap::from([(0x40u64, "fib".to_string())]);
        let blank = HashMap::from([(0x40u64, "   ".to_string())]);
        let elsewhere = HashMap::from([(0x99u64, "other".to_string())]);
        for analyst in [None, Some(&HashMap::new()), Some(&blank), Some(&elsewhere)] {
            assert_eq!(
                resolve_outer_function_name_with_analyst("sub_40", 0x40, &addr_map, analyst),
                "fib",
                "the rank walk must still run"
            );
            assert_eq!(
                resolve_outer_function_name_with_analyst("validate", 0x40, &addr_map, analyst),
                "validate",
                "a wanted discovered name must still short-circuit"
            );
        }
    }
}

#[cfg(test)]
mod outer_name_tests {
    use super::resolve_outer_function_name;
    use std::collections::HashMap;

    fn map(pairs: &[(u64, &str)]) -> HashMap<u64, String> {
        pairs.iter().map(|(a, n)| (*a, n.to_string())).collect()
    }

    /// The bug this fixes, exactly: gcc -O2 emits `fib.localalias` at the same
    /// address as the global `fib`. Naming the function `fib_localalias` means no
    /// source declares it, DecBench cannot match it, and the binary scores NO graph
    /// edit distance at all while angr scores it normally.
    #[test]
    fn an_internal_alias_loses_to_the_plain_name_at_the_same_address() {
        let m = map(&[(0x1100, "fib")]);
        assert_eq!(
            resolve_outer_function_name("fib.localalias", 0x1100, &m),
            "fib"
        );
    }

    /// Every internal suffix the ranking knows about, not just `.localalias`.
    #[test]
    fn every_internal_suffix_loses_to_the_plain_name() {
        let m = map(&[(0x2000, "work")]);
        for alias in [
            "work.cold",
            "work.part.0",
            "work.isra.3",
            "work.constprop.1",
            "work.lto_priv.42",
        ] {
            assert_eq!(
                resolve_outer_function_name(alias, 0x2000, &m),
                "work",
                "{alias}"
            );
        }
    }

    /// A synthesised name still defers to a real symbol — the original behaviour.
    #[test]
    fn a_synthesised_name_still_defers_to_a_real_symbol() {
        let m = map(&[(0x1100, "fib")]);
        assert_eq!(resolve_outer_function_name("sub_1100", 0x1100, &m), "fib");
    }

    /// A perfectly good discovered name is never second-guessed.
    #[test]
    fn a_plain_discovered_name_is_kept() {
        let m = map(&[(0x1100, "something_else")]);
        assert_eq!(resolve_outer_function_name("fib", 0x1100, &m), "fib");
    }

    /// If the ONLY symbol at the address is itself an alias, keep what we had
    /// rather than swapping one unusable name for another.
    #[test]
    fn an_alias_is_kept_when_the_map_offers_no_better_name() {
        let m = map(&[(0x1100, "fib.cold")]);
        assert_eq!(
            resolve_outer_function_name("fib.localalias", 0x1100, &m),
            "fib.localalias"
        );
        let empty = map(&[]);
        assert_eq!(
            resolve_outer_function_name("fib.localalias", 0x1100, &empty),
            "fib.localalias"
        );
    }
}
