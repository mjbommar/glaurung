//! Criterion benchmarks for the ANALYSIS layer (`src/analysis/`).
//!
//! This layer runs *before* the IR pipeline: it turns a file of bytes into
//! functions, basic blocks and a call graph, plus the format-specific side
//! tables that discovery leans on (PLT/IAT maps, jump tables, vtables,
//! `.eh_frame` landing pads, code->data xrefs).
//!
//! Two tiers, matching where regressions actually get attributed:
//!
//! 1. **Micro** — one module, one small real binary, so a slowdown points at
//!    exactly one file in `src/analysis/`.
//! 2. **Whole-binary sweep** — `analyze_functions_bytes` over real binaries of
//!    increasing size, with `Throughput::Bytes` so criterion reports MB/s and
//!    superlinear growth is visible as a *falling* throughput number.
//!
//! Every input is a real binary on disk. Fixtures under
//! `tests/decompiler_fixtures/build/` are gitignored and built by the fixture
//! harness; each bench is skipped (not faked) when its input is absent, exactly
//! as `benches/triage.rs` does.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use std::collections::BTreeMap;
use std::fs;

use glaurung::analysis::cfg::{
    analyze_functions_bytes, analyze_functions_image, scan_pe_code_pointers, Budgets,
};
use glaurung::analysis::dispatch::DispatchTracker;
use glaurung::analysis::elf_plt::elf_plt_map;
use glaurung::analysis::exception::{eh_frame_functions, extract_exception_call_sites};
use glaurung::analysis::jump_table::discover_jump_tables;
use glaurung::analysis::pe_iat::{pe_iat_map, pe_import_call_sites, pe_import_thunk_map};
use glaurung::analysis::vtable::discover_vtables;
use glaurung::analysis::xrefs::{code_to_data_xrefs, data_ranges_for_xrefs, function_data_xrefs};
use glaurung::core::address::{Address, AddressKind};
use glaurung::core::disassembler::{Architecture, Disassembler};
use glaurung::core::function::Function;
use glaurung::core::instruction::Instruction;
use glaurung::disasm::registry;
use glaurung::program::image::ProgramImage;

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

const FIXTURES: &str = "tests/decompiler_fixtures/build";

/// Whole-binary size ladder, smallest to largest. Real ELF shared objects from
/// the decompiler fixture corpus; the sizes span roughly 14 KB -> 12.8 MB, which
/// is the widest real range the corpus offers.
const SIZE_LADDER: &[&str] = &[
    "01_conditional_polarity-gcc-O2strip.so", //  ~14 KB, minimal C
    "10_cpp_runtime_shapes-gcc-O0.so",        //  ~28 KB, C++ with EH
    "153_many_live_locals-gcc-O2.so",         //  ~83 KB, register-pressure heavy
    "167_rust_trait_objects-rustc-O2strip.so", // ~359 KB, stripped Rust + std
    "168_rust_enum_niche-rustc-O2.so",        // ~12.8 MB, Rust + full DWARF
];

/// One small C++ fixture, used wherever a micro bench needs landing pads,
/// vtables and a non-trivial `.eh_frame`.
const CPP_FIXTURE: &str = "10_cpp_runtime_shapes-gcc-O0.so";
/// One small C fixture with dense and sparse switch tables.
const SWITCH_FIXTURE: &str = "106_switch_shapes_dense_sparse-gcc-O0.so";
/// Explicit C++ vtable layout fixture.
const VTABLE_FIXTURE: &str = "132_cpp_vtable_layout-gcc-O0.so";

/// Cross-architecture ELF inputs. The fixture corpus is x86-64 only, so
/// architecture breadth comes from `samples/`.
const ARCH_ELF: &[(&str, &str)] = &[
    (
        "x86_64",
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-c-gcc-O2",
    ),
    (
        "aarch64",
        "samples/binaries/platforms/linux/arm64/export/native/clang/O2/hello-c-clang-O2",
    ),
    (
        "armv7",
        "samples/binaries/platforms/linux/arm64/export/cross/armhf/hello-armhf-gcc",
    ),
    (
        "riscv64",
        "samples/binaries/platforms/linux/arm64/export/cross/riscv64/hello-riscv64-gcc",
    ),
];

/// PE inputs — a different code path end to end (`pe_iat` rather than
/// `elf_plt`, `.pdata`/export-table seeding rather than `.eh_frame`).
const PE_BINARIES: &[(&str, &str)] = &[
    (
        "pe32-i386-mingw",
        "samples/binaries/platforms/windows/i386/export/windows/i686/O0/hello-c-mingw32-O0.exe",
    ),
    (
        "pe64-msvc-small",
        "samples/binaries/platforms/windows/vendor/realworld/win11-acledit.dll",
    ),
    (
        "pe64-msvc-large",
        "samples/binaries/platforms/windows/vendor/realworld/win10-webservices.dll",
    ),
];

fn fixture(name: &str) -> Option<Vec<u8>> {
    fs::read(format!("{FIXTURES}/{name}")).ok()
}

fn sample(path: &str) -> Option<Vec<u8>> {
    fs::read(path).ok()
}

// ---------------------------------------------------------------------------
// Setup helpers — everything here runs OUTSIDE the measured closure.
// ---------------------------------------------------------------------------

/// Executable VA ranges, taken from the indexed image rather than re-parsed.
///
/// `cfg::parse_exec_regions` is private, and `jump_table`/`vtable` take the
/// predicate as a closure precisely so a caller can supply it.
fn exec_ranges(data: &[u8]) -> Vec<std::ops::Range<u64>> {
    ProgramImage::from_bytes(data.to_vec())
        .map(|image| image.executable_ranges().cloned().collect())
        .unwrap_or_default()
}

fn in_ranges(ranges: &[std::ops::Range<u64>], va: u64) -> bool {
    ranges.iter().any(|r| r.contains(&va))
}

/// Linearly disassemble up to `max_bytes` of `.text` into a real instruction
/// stream, for the benches that consume instructions rather than bytes.
fn disassemble_text(data: &[u8], max_bytes: usize) -> Vec<Instruction> {
    let Ok(image) = ProgramImage::from_bytes(data.to_vec()) else {
        return Vec::new();
    };
    let arch: Architecture = image.arch().into();
    let Some(dis) = registry::for_arch(arch, image.endianness()) else {
        return Vec::new();
    };
    let bits: u8 = if image.arch().is_64_bit() { 64 } else { 32 };
    let Some(text) = image.sections().find(|s| s.name() == ".text") else {
        return Vec::new();
    };
    let base = text.address();
    let bytes = text.data();
    let limit = bytes.len().min(max_bytes);

    let mut out = Vec::new();
    let mut off = 0usize;
    while off < limit {
        let Ok(addr) = Address::new(AddressKind::VA, base + off as u64, bits, None, None) else {
            break;
        };
        match dis.disassemble_instruction(&addr, &bytes[off..]) {
            Ok(ins) => {
                let len = usize::from(ins.length).max(1);
                out.push(ins);
                off += len;
            }
            Err(_) => off += 1,
        }
    }
    out
}

fn discovered_functions(data: &[u8]) -> Vec<Function> {
    analyze_functions_bytes(data, &Budgets::default()).0
}

// ---------------------------------------------------------------------------
// Tier 2 — whole-binary sweep
// ---------------------------------------------------------------------------

/// `analyze_functions_bytes` over the whole size ladder.
///
/// `Throughput::Bytes` over the file size means criterion reports MB/s: if the
/// analysis is linear in input size the number holds roughly flat across the
/// ladder, and any collapse in MB/s as the binaries grow is superlinear cost.
fn bench_whole_binary_discovery(c: &mut Criterion) {
    let mut group = c.benchmark_group("analysis-cfg-sweep");
    // The top of the ladder is multi-second; the default 100 samples would make
    // one run of this bench take longer than the whole rest of the file.
    group.sample_size(10);

    for name in SIZE_LADDER {
        let Some(data) = fixture(name) else { continue };
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_function(*name, |b| {
            b.iter_batched(
                || data.clone(),
                |buf| {
                    let _ = analyze_functions_bytes(&buf, &Budgets::default());
                },
                BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

/// The `ProgramImage` path: index once, then discover against the shared index.
///
/// Split into the two halves so a regression attributes to the parse/index step
/// or to discovery itself, and so the image path can be compared against the
/// byte-slice path above on the same input.
fn bench_image_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("analysis-cfg-image");
    group.sample_size(20);

    for name in [
        "10_cpp_runtime_shapes-gcc-O0.so",
        "153_many_live_locals-gcc-O2.so",
    ] {
        let Some(data) = fixture(name) else { continue };

        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_function(format!("index/{name}"), |b| {
            b.iter_batched(
                || data.clone(),
                |buf| {
                    let _ = ProgramImage::from_bytes(buf);
                },
                BatchSize::LargeInput,
            )
        });

        let Ok(image) = ProgramImage::from_bytes(data.clone()) else {
            continue;
        };
        group.bench_function(format!("discover/{name}"), |b| {
            b.iter(|| {
                let _ = analyze_functions_image(&image, &Budgets::default());
            })
        });
    }

    group.finish();
}

/// Whole-binary discovery across architectures and formats.
///
/// The lifters, prologue scanners and PLT/IAT recovery are all arch- and
/// format-specific, so a change that is free on x86-64 can be expensive on
/// aarch64 or on PE. These are the lanes that say so.
fn bench_arch_and_format(c: &mut Criterion) {
    let mut group = c.benchmark_group("analysis-cfg-arch");
    group.sample_size(20);

    for (label, path) in ARCH_ELF.iter().chain(PE_BINARIES.iter()) {
        let Some(data) = sample(path) else { continue };
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_function(*label, |b| {
            b.iter_batched(
                || data.clone(),
                |buf| {
                    let _ = analyze_functions_bytes(&buf, &Budgets::default());
                },
                BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Tier 1 — micro benches, one module each
// ---------------------------------------------------------------------------

/// `src/analysis/elf_plt.rs` — PLT stub VA -> imported symbol name.
fn bench_elf_plt(c: &mut Criterion) {
    let mut group = c.benchmark_group("analysis-elf-plt");

    let mut inputs: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(data) = fixture(CPP_FIXTURE) {
        inputs.push((CPP_FIXTURE.to_string(), data));
    }
    for (label, path) in ARCH_ELF {
        if let Some(data) = sample(path) {
            inputs.push(((*label).to_string(), data));
        }
    }

    for (label, data) in &inputs {
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_function(format!("elf_plt_map/{label}"), |b| {
            b.iter(|| {
                let _ = elf_plt_map(data);
            })
        });
    }

    group.finish();
}

/// `src/analysis/pe_iat.rs` and the PE code-pointer scan in `cfg/scan.rs`.
fn bench_pe_imports(c: &mut Criterion) {
    let mut group = c.benchmark_group("analysis-pe-iat");

    for (label, path) in PE_BINARIES {
        let Some(data) = sample(path) else { continue };
        group.throughput(Throughput::Bytes(data.len() as u64));

        group.bench_function(format!("pe_iat_map/{label}"), |b| {
            b.iter(|| {
                let _ = pe_iat_map(&data);
            })
        });
        group.bench_function(format!("pe_import_thunk_map/{label}"), |b| {
            b.iter(|| {
                let _ = pe_import_thunk_map(&data);
            })
        });
        group.bench_function(format!("pe_import_call_sites/{label}"), |b| {
            b.iter(|| {
                let _ = pe_import_call_sites(&data);
            })
        });
        group.bench_function(format!("scan_pe_code_pointers/{label}"), |b| {
            b.iter(|| {
                let _ = scan_pe_code_pointers(&data);
            })
        });
    }

    group.finish();
}

/// `src/analysis/jump_table.rs` — rodata scan for relative-offset tables.
fn bench_jump_tables(c: &mut Criterion) {
    let mut group = c.benchmark_group("analysis-jump-table");

    for name in [SWITCH_FIXTURE, "154_wide_switch-gcc-O2.so", CPP_FIXTURE] {
        let Some(data) = fixture(name) else { continue };
        let ranges = exec_ranges(&data);
        if ranges.is_empty() {
            continue;
        }
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_function(format!("discover_jump_tables/{name}"), |b| {
            b.iter(|| {
                let _ = discover_jump_tables(&data, |va| in_ranges(&ranges, va));
            })
        });
    }

    group.finish();
}

/// `src/analysis/vtable.rs` — C++ vtable recovery from rodata.
fn bench_vtables(c: &mut Criterion) {
    let mut group = c.benchmark_group("analysis-vtable");

    for name in [
        VTABLE_FIXTURE,
        "133_cpp_multiple_inheritance-gcc-O0.so",
        CPP_FIXTURE,
    ] {
        let Some(data) = fixture(name) else { continue };
        let ranges = exec_ranges(&data);
        if ranges.is_empty() {
            continue;
        }
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_function(format!("discover_vtables/{name}"), |b| {
            b.iter(|| {
                let _ = discover_vtables(&data, |va| in_ranges(&ranges, va));
            })
        });
    }

    group.finish();
}

/// `src/analysis/exception.rs` — `.eh_frame` FDE walk and LSDA call-site table.
///
/// C++ fixtures are the point: a C binary has an `.eh_frame` but almost no
/// LSDA, so only a C++ landing-pad corpus exercises the call-site decoder.
fn bench_exception(c: &mut Criterion) {
    let mut group = c.benchmark_group("analysis-exception");

    let mut names = vec![
        CPP_FIXTURE,
        "132_cpp_vtable_layout-gcc-O0.so",
        "134_cpp_virtual_inheritance-gcc-O0.so",
        "01_conditional_polarity-gcc-O2strip.so", // C control: near-empty LSDA
    ];
    // Rust unwinding — a much larger `.eh_frame` than any C++ fixture here.
    names.push("170_rust_panic_unwind-rustc-O2strip.so");

    for name in names {
        let Some(data) = fixture(name) else { continue };
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_function(format!("eh_frame_functions/{name}"), |b| {
            b.iter(|| {
                let _ = eh_frame_functions(&data);
            })
        });
        group.bench_function(format!("extract_exception_call_sites/{name}"), |b| {
            b.iter(|| {
                let _ = extract_exception_call_sites(&data);
            })
        });
    }

    group.finish();
}

/// `src/analysis/xrefs.rs` — data-range construction and code->data references.
///
/// `code_to_data_xrefs` takes an already decoded instruction stream, so the
/// disassembly is setup and is deliberately not measured here.
fn bench_xrefs(c: &mut Criterion) {
    let mut group = c.benchmark_group("analysis-xrefs");

    for name in [CPP_FIXTURE, "153_many_live_locals-gcc-O2.so"] {
        let Some(data) = fixture(name) else { continue };
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_function(format!("data_ranges_for_xrefs/{name}"), |b| {
            b.iter(|| {
                let _ = data_ranges_for_xrefs(&data);
            })
        });

        let ranges = data_ranges_for_xrefs(&data);
        let insns = disassemble_text(&data, 64 * 1024);
        if !ranges.is_empty() && !insns.is_empty() {
            // Instructions, not file bytes: this entry point consumes a decoded
            // stream, so per-instruction cost is the number that means anything.
            group.throughput(Throughput::Elements(insns.len() as u64));
            group.bench_function(format!("code_to_data_xrefs/{name}"), |b| {
                b.iter(|| {
                    let _ = code_to_data_xrefs(&insns, &ranges, 64, usize::MAX);
                })
            });
            group.throughput(Throughput::Bytes(data.len() as u64));
        }

        let funcs = discovered_functions(&data);
        if !funcs.is_empty() {
            group.bench_function(format!("function_data_xrefs/{name}"), |b| {
                b.iter(|| {
                    let _ = function_data_xrefs(&data, &funcs, usize::MAX);
                })
            });
        }
    }

    // aarch64 takes a different path inside `code_to_data_xrefs`: ADRP+ADD/LDR
    // pairs are reconstructed across two instructions before the scalar pass.
    if let Some(data) = sample(ARCH_ELF[1].1) {
        let ranges = data_ranges_for_xrefs(&data);
        let insns = disassemble_text(&data, 64 * 1024);
        if !ranges.is_empty() && !insns.is_empty() {
            group.throughput(Throughput::Elements(insns.len() as u64));
            group.bench_function("code_to_data_xrefs/aarch64-adrp", |b| {
                b.iter(|| {
                    let _ = code_to_data_xrefs(&insns, &ranges, 64, usize::MAX);
                })
            });
        }
    }

    group.finish();
}

/// `src/analysis/dispatch.rs` — the abstract register tracker that resolves
/// indirect transfers.
///
/// `observe` is called once per instruction on every CFG walk, so its per
/// instruction cost is multiplied by the whole program; `resolve` is called
/// only at indirect transfers. Both are measured over a real instruction
/// stream, with the disassembly hoisted into setup.
fn bench_dispatch(c: &mut Criterion) {
    let mut group = c.benchmark_group("analysis-dispatch");

    let mut inputs: Vec<(String, Vec<Instruction>)> = Vec::new();
    for name in [SWITCH_FIXTURE, "154_wide_switch-gcc-O2.so"] {
        if let Some(data) = fixture(name) {
            let insns = disassemble_text(&data, 128 * 1024);
            if !insns.is_empty() {
                inputs.push((name.to_string(), insns));
            }
        }
    }
    // aarch64 and armv7 drive separate branches of the tracker (ADRP/ADR
    // materialization, Thumb table branches).
    for (label, path) in [ARCH_ELF[1], ARCH_ELF[2]] {
        if let Some(data) = sample(path) {
            let insns = disassemble_text(&data, 128 * 1024);
            if !insns.is_empty() {
                inputs.push((label.to_string(), insns));
            }
        }
    }

    let tables: BTreeMap<u64, Vec<u64>> = BTreeMap::new();

    for (label, insns) in &inputs {
        group.throughput(Throughput::Elements(insns.len() as u64));
        group.bench_function(format!("tracker_observe/{label}"), |b| {
            b.iter_batched(
                DispatchTracker::new,
                |mut tracker| {
                    for ins in insns {
                        tracker.observe(ins);
                    }
                },
                BatchSize::SmallInput,
            )
        });
        group.bench_function(format!("tracker_observe_resolve/{label}"), |b| {
            b.iter_batched(
                DispatchTracker::new,
                |mut tracker| {
                    for ins in insns {
                        tracker.observe(ins);
                        let _ = tracker.resolve(ins, &tables);
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_whole_binary_discovery,
    bench_image_path,
    bench_arch_and_format,
    bench_elf_plt,
    bench_pe_imports,
    bench_jump_tables,
    bench_vtables,
    bench_exception,
    bench_xrefs,
    bench_dispatch,
);
criterion_main!(benches);
