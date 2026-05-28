
## 2026-05-28 — First-class PDB symbol naming for Windows PEs
- **Problem:** `kickoff` discovered all functions but named only PE exports
  (~5%); the rest stayed `sub_<addr>`. glaurung had a PDB *resolver*
  (`g.symbols.pdb_symbol_map`, local-cache-only) but (a) nothing filled the
  cache and (b) kickoff never called it.
- **Fix:**
  - New `glaurung/pdb_fetch.py` — pure-stdlib CodeView RSDS parser + MS
    symbol-server downloader (`ensure_pdb_cached`). The genuinely-missing
    capability.
  - Wired `--pdb-cache` / `--fetch-pdb` (+ `$GLAURUNG_PDB_CACHE` default)
    into `kickoff_analysis` + the kickoff CLI; applies the PDB public map to
    `function_names` with `set_by="pdb"`.
- **Verified:** srvsvc.dll 43→783, srvnet.sys 221→959, spoolsv.exe 314→2278
  named. Names match `llvm-pdbutil --publics` at 100% precision (959/959);
  the 28-name delta vs raw publics is ICF folding (18 VAs share WPP_SF_*
  duplicates) — per-VA naming is correct.
- **Tests:** `test_pdb_fetch.py` (5) + `test_kickoff_pdb_naming.py` (2) green;
  ruff + ty clean. Pre-existing `test_kickoff_analysis::...c2_demo` failure is
  unrelated (fails with these changes stashed).
- **Future:** preserve ICF aliases via `function_names.aliases_json`; wire
  auto-fetch into decompile/explain/windows-risk too (currently cache-only).
