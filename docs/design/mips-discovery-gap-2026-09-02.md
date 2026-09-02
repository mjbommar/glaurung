# MIPS discovery gap on Cisco Talos Dataset-1 (2026-09-02)

## Reproduction

`GLAURUNG_CISCO_CORPUS=$HOME/.cache/glaurung/corpora/cisco-talos-dataset1 cargo
test --test identity_retrieval -- --nocapture cisco` reproduces the reported
numbers exactly, over the default 9-slice, 3-binary (`ncat`, `nmap`, `nping`)
lane defined in `tests/identity_retrieval/cisco.rs`:

```
mips32-gcc-9-O2: 259 functions, 223 (86%) recover <5 blocks
mips64-gcc-9-O2: 279 functions, 159 (57%) recover <5 blocks
x64-gcc-9-O0:    335 functions,   0 (0%)
x64-gcc-9-O2:    229 functions,   0 (0%)
```

`load_image()` (`tests/identity_retrieval/cisco.rs:684-773`) seeds
`analyze_functions_bytes_with_seeds` with every ground-truth `fva` in the
binary at once and looks each one up by exact entry VA
(`by_va.get(&row.fva)`, line 743). The run-wide totals line prints
`no-cfg 0` - **every requested address produced a `Function` entry**, so class
(a) "address not discovered at all" is 0/259 and 0/279. All 223+159 misses are
therefore class (c): discovered at the right address, but with fewer than
`MIN_BASIC_BLOCKS` (5) blocks. Class (b) (address absorbed into another
function's extent) does not apply under this seeded methodology, since
`discover_function` is forced to start exactly at each requested VA.

## Localised cause

`analyze_functions_bytes_with_seeds` -> `analyze_functions_bytes_within`
(`src/analysis/cfg/packed.rs`, image=None for this call site) ->
`analyze_functions_unpacked` (`src/analysis/cfg/worklist.rs:96-97`):

```rust
let (regions, arch, end, entry) =
    image.map_or_else(|| parse_exec_regions(data), parse_exec_regions_in);
```

With no `ProgramImage`, this calls `parse_exec_regions`
(`src/analysis/cfg/image_view.rs:32-58`), which hardcodes endianness by
architecture family:

```rust
// Default endian by architecture family; object::File doesn't expose global endianness
endian = match arch {
    BArch::PPC | BArch::PPC64 => Endianness::Big,
    _ => Endianness::Little,
};
```

That comment is false for the `object` crate actually vendored here
(0.36.7): `Object::endianness()` / `Object::is_little_endian()` read the
ELF `e_ident[EI_DATA]` byte directly (`object-0.36.7/src/read/traits.rs:94-104`).
The **other** code path already does this correctly:
`ProgramImage::from_bytes` (`src/program/image.rs:176-179`) computes
`endianness` from `object.is_little_endian()` and `parse_exec_regions_in`
(`image_view.rs:150`) uses `image.endianness()`. The bug is confined to the
byte-only `parse_exec_regions`, which every Dataset-1 MIPS slice hits because
the Cisco loader calls the `_bytes_with_seeds` entry point with no image.

Every mips32/mips64 binary in Dataset-1 is big-endian (`file`: "ELF 32-bit MSB
... MIPS"), so this path initializes the Capstone MIPS backend
(`src/disasm/capstone.rs:118-134`, `cs_arch_mode`) in **little-endian** mode
against big-endian bytes.

## Cross-check

No `mips*-linux-gnu-objdump` on this host and system `objdump` (binutils
2.46) lacks a MIPS target (`objdump -d ...: can't disassemble for
architecture UNKNOWN!`). Used capstone directly instead
(`uv run --with capstone --with pyelftools python3 ...`), decoding two missed
ground-truth functions from `mips32-gcc-9-O2_ncat` in both modes:

```
nsock_timer_create @ 0x4193a0 (7 blocks per IDA):
  BIG (correct):   lui $gp,0x48 ; addiu $sp,$sp,-0x38 ; addiu $gp,$gp,-0x1b10 ; sw $s1,0x2c($sp) ...
  LITTLE (bug):    <0 instructions decoded>

ncat_recv @ 0x409b4c (10 blocks per IDA):
  BIG (correct):   lui $gp,0x48 ; sw $zero,($a3) ; addiu $sp,$sp,-0x30 ; addiu $gp,$gp,-0x1b10 ...
  LITTLE (bug):    <0 instructions decoded>
```

Under the endianness the code actually selects, Capstone cannot decode even
the first instruction of either function -- an immediate class (d)
disassembly failure that yields a 0- or 1-block `Function`, not a gradually
degrading CFG walk. A third check earlier in the same run (offset
`0x403fc0`) showed Capstone *can* occasionally limp a few instructions
under the wrong endianness before erroring (`swc1 $f0,-0x4cd9($zero)`,
`beqz $v1,0x414860`) -- garbage operands that would misdirect the walker if
decode didn't fail outright first.

## Fix estimate and blast radius

One function, `parse_exec_regions` in `src/analysis/cfg/image_view.rs:53-57`:
replace the hardcoded `_ => Endianness::Little` arm with the same
`obj.is_little_endian()` read `ProgramImage::from_bytes` already does at
`src/program/image.rs:176-179`. No signature change, no caller update beyond
recompiling; `parse_exec_regions_in` and every image-backed call site are
already correct and untouched. Estimated size: ~5 changed lines in one file,
plus a regression test in `tests/identity_retrieval/cisco.rs` or
`src/analysis/cfg/image_view.rs`'s own unit tests asserting a big-endian MIPS
sample decodes non-trivially.

This is entirely inside `src/analysis/cfg/` and `src/disasm/`; it does not
touch `src/ir/` at all, so it is outside the concurrent session's
`src/ir/structure_v2/` blast radius.

A residual, smaller issue independent of endianness: `classify_ctrl_flow`
and `is_unconditional_branch_mnemonic` for `BArch::MIPS`/`MIPS64`
(`src/analysis/cfg/ctrl_flow.rs:305-320,` `~348`) mark `jr` as a branch
rather than a return and don't special-case `j`/`jr` in the unconditional-jump
list, and no branch-delay-slot handling exists anywhere in `walk`/`ctrl_flow`.
Once decode is fixed, this would still cost some real MIPS functions correct
block splits (delay-slot instructions attributed to the wrong block, `jr $ra`
not closing a function) -- worth a follow-up measurement once the endianness
fix lands, but it is a second, smaller defect, not the explanation for the
86%/57% figures above.

Commands used: `cargo test --test identity_retrieval -- --nocapture cisco`
(with `GLAURUNG_CISCO_CORPUS` set); `uv run --with capstone --with pyelftools
python3 -c ...` for the endianness cross-check; `objdump -i` / `objdump -d`
to confirm no local MIPS binutils target; `file` on the two nmap-project
mips32/mips64 binaries to confirm MSB byte order.
