"""`list_symbols()` reports what the binary says, not a hardcoded default.

The defect
----------

`SymbolSummary` carries `stripped`, `debug_info_present`, `tls_used`,
`tls_callback_count`, `tls_callback_vas` and `pdb_path`. `src/symbols/pe.rs`
and `src/symbols/elf.rs` compute every one of them correctly. The Python
binding did not call either: `src/python_bindings/symbols.rs` built its own
summary by hand from a name-list helper and filled the rest in with
``false`` / ``None`` under a ``// TODO: detect this`` comment, on both the
`list_symbols` and `list_symbols_demangled` paths.

The result was a silent, uniform lie. Measured before the fix:

    dbg.elf       (file: "with debug_info, not stripped")  stripped=False debug_info=False
    stripped.elf  (file: "stripped")                       stripped=False debug_info=False
    probe.dll     (CodeView entry, PDB path present)       debug_info=False pdb_path=None

Identical answers for a stripped and an unstripped build of the same source.
Nothing raised; every caller branching on these took the "no debug info,
not stripped, no TLS" path for every binary ever passed to this API.

Why real binaries rather than a synthesized header
--------------------------------------------------

Each field is a property of a real container structure -- a COFF symbol table
count, a CodeView debug directory entry, a TLS data directory. A hand-built
header would assert my model of the format instead of the format, and the bug
being fixed is exactly a wrong model going unchecked.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import glaurung

ROOT = Path(__file__).resolve().parent.parent.parent

#: A real Windows DLL that carries all three PE structures at once: no COFF
#: symbol table (stripped), a CodeView entry naming `DismCore.pdb`, and a TLS
#: directory at RVA 0x30088.
PE_SAMPLE = (
    ROOT / "samples/binaries/platforms/windows/vendor/realworld/win10-dismcore.dll"
)

SRC = "int f(int x){return x*2;}\nint main(void){return f(21);}\n"


@pytest.fixture(scope="module")
def elf_pair(tmp_path_factory) -> tuple[Path, Path]:
    """An unstripped-with-DWARF ELF and a stripped copy of the same bytes."""
    if not shutil.which("gcc") or not shutil.which("strip"):
        pytest.skip("needs gcc and strip")
    d = tmp_path_factory.mktemp("elfpair")
    src = d / "t.c"
    src.write_text(SRC)
    dbg, stripped = d / "dbg.elf", d / "stripped.elf"
    subprocess.run(["gcc", "-g", "-O0", "-o", str(dbg), str(src)], check=True, cwd=d)
    shutil.copy(dbg, stripped)
    subprocess.run(["strip", str(stripped)], check=True)
    return dbg, stripped


def summary(path: Path):
    return glaurung.symbols.list_symbols(str(path))


# --- ELF ------------------------------------------------------------------


def test_a_stripped_elf_reports_stripped(elf_pair):
    _, stripped = elf_pair
    assert summary(stripped).stripped is True, (
        "a stripped binary reported stripped=False. This was hardcoded; "
        "src/symbols/elf.rs computes it correctly and was never called."
    )


def test_an_unstripped_elf_reports_not_stripped(elf_pair):
    """The other half: a field that is always True is as useless as always False."""
    dbg, _ = elf_pair
    assert summary(dbg).stripped is False


def test_dwarf_is_reported_as_debug_info(elf_pair):
    dbg, _ = elf_pair
    assert summary(dbg).debug_info_present is True, (
        "an ELF built with -g reported debug_info_present=False"
    )


def test_a_stripped_elf_has_no_debug_info(elf_pair):
    _, stripped = elf_pair
    assert summary(stripped).debug_info_present is False


# --- PE -------------------------------------------------------------------


@pytest.fixture(scope="module")
def pe_summary():
    if not PE_SAMPLE.is_file() or PE_SAMPLE.stat().st_size < 4096:
        pytest.skip(f"{PE_SAMPLE.name} absent or an unfetched LFS pointer")
    return summary(PE_SAMPLE)


def test_pe_codeview_entry_is_reported_as_debug_info(pe_summary):
    """A PE whose debug directory names a PDB has debug info, in the only
    sense that matters to an analyst: types and names are obtainable."""
    assert pe_summary.debug_info_present is True


def test_pe_pdb_path_is_reported(pe_summary):
    """`pdb_path` is how the PDB is located. None means it cannot be."""
    assert pe_summary.pdb_path, "CodeView entry names DismCore.pdb; got None"
    assert pe_summary.pdb_path.lower().endswith(".pdb"), pe_summary.pdb_path


def test_pe_tls_directory_is_reported(pe_summary):
    """TLS callbacks run BEFORE the entry point, so a malware analyst who
    trusts `tls_used=False` looks at the wrong code first."""
    assert pe_summary.tls_used is True


def test_pe_without_a_coff_symbol_table_is_stripped(pe_summary):
    assert pe_summary.stripped is True


# --- both binding paths ---------------------------------------------------


def test_the_demangled_path_agrees_with_the_plain_one(elf_pair):
    """`list_symbols_demangled` had the SAME hardcoded block, separately.

    Fixing one and not the other would leave a caller's answer depending on
    which spelling they happened to use.
    """
    dbg, _ = elf_pair
    plain = glaurung.symbols.list_symbols(str(dbg))
    dem = glaurung.symbols.list_symbols_demangled(str(dbg))
    for field in ("stripped", "debug_info_present", "tls_used", "pdb_path"):
        assert getattr(plain, field) == getattr(dem, field), (
            f"{field} differs between list_symbols and list_symbols_demangled"
        )
