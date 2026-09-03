//! What the corpus actually declares about its own effects.
//!
//! These are measurements, not assertions about a design. The reporting test is
//! `#[ignore]`d because it prints a histogram rather than checking one; the
//! invariant tests below run every time and are what stops the numbers from
//! silently getting worse.
//!
//! Run the report with:
//!
//! ```text
//! cargo test --features python-ext effect_census -- --ignored --nocapture
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
use crate::analysis::entry::va_to_code_file_offset;
use crate::core::address::{Address, AddressKind};
use crate::core::binary::{Arch, Endianness};
use crate::core::disassembler::Disassembler;
use crate::core::function::FunctionFlags;
use crate::disasm::registry;
use crate::ir::effect_census::{census_into, EffectCensus};
use crate::ir::lift_function::lift_function_from_bytes;
use crate::ir::types::{LlirFunction, Op};

/// One evidence lane. Compiler identity comes from the committed metadata
/// sidecar. Optimisation is taken from its output path when present; artifacts
/// which do not record a level say `unknown` rather than guessing one.
#[derive(Debug, Clone, Copy)]
struct CorpusSample {
    path: &'static str,
    arch: Arch,
    compiler: &'static str,
    optimization: &'static str,
}

/// A cross-section of the committed sample corpus: four lifted targets,
/// multiple compilers, hand-written assembly, and several optimisation modes.
const CORPUS: &[CorpusSample] = &[
    CorpusSample {
        path:
            "samples/binaries/platforms/windows/i386/export/windows/i686/O2/hello-c-mingw32-O2.exe",
        arch: Arch::X86,
        compiler: "i686-w64-mingw32-gcc",
        optimization: "O2",
    },
    CorpusSample {
        path: "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0",
        arch: Arch::X86_64,
        compiler: "gcc",
        optimization: "O0",
    },
    CorpusSample {
        path: "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        arch: Arch::X86_64,
        compiler: "g++",
        optimization: "O2",
    },
    CorpusSample {
        path: "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/c2_demo-gcc-O2",
        arch: Arch::X86_64,
        compiler: "gcc",
        optimization: "O2",
    },
    CorpusSample {
        path: "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2",
        arch: Arch::X86_64,
        compiler: "g++",
        optimization: "O2",
    },
    CorpusSample {
        path: "samples/binaries/platforms/linux/amd64/rust/hello-rust-release",
        arch: Arch::X86_64,
        compiler: "rustc",
        optimization: "release",
    },
    CorpusSample {
        path: "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc",
        arch: Arch::AArch64,
        compiler: "aarch64-linux-gnu-gcc",
        optimization: "unknown",
    },
    CorpusSample {
        path: "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-asm-arm64-as",
        arch: Arch::AArch64,
        compiler: "aarch64-linux-gnu-as",
        optimization: "not-applicable",
    },
    CorpusSample {
        path: "samples/binaries/platforms/linux/arm64/export/native/gcc/O1/hello-cpp-g++-O1",
        arch: Arch::AArch64,
        compiler: "g++",
        optimization: "O1",
    },
    CorpusSample {
        path: "samples/binaries/platforms/linux/arm64/export/cross/armhf/hello-armhf-gcc",
        arch: Arch::ARM,
        compiler: "arm-linux-gnueabihf-gcc",
        optimization: "unknown",
    },
];

fn census_corpus(only_arch: Option<Arch>) -> (EffectCensus, usize, usize) {
    let budgets = Budgets {
        max_functions: 96,
        max_blocks: 512,
        max_instructions: 60_000,
        timeout_ms: 4000,
        total_timeout_ms: 0,
    };
    let mut total = EffectCensus::default();
    let mut files = 0usize;
    let mut functions = 0usize;
    for sample in CORPUS {
        if only_arch.is_some_and(|selected| selected != sample.arch) {
            continue;
        }
        let path = Path::new(sample.path);
        if !path.exists() {
            continue;
        }
        files += 1;
        let data = std::fs::read(path).expect("read sample");
        let (discovered, _call_graph) = analyze_functions_bytes(&data, &budgets);
        for function in &discovered {
            if let Ok(lifted) = lift_function_from_bytes(&data, function, sample.arch) {
                census_into(&lifted, &mut total);
                functions += 1;
            }
        }
    }
    (total, files, functions)
}

fn corpus_census() -> (EffectCensus, usize, usize) {
    census_corpus(None)
}

fn corpus_census_for_arch(arch: Arch) -> (EffectCensus, usize, usize) {
    census_corpus(Some(arch))
}

#[test]
fn every_corpus_sample_has_an_explicit_provenance_lane() {
    let mut paths = BTreeSet::new();
    for sample in CORPUS {
        assert!(
            paths.insert(sample.path),
            "duplicate census path: {}",
            sample.path
        );
        assert!(
            !sample.compiler.trim().is_empty(),
            "missing compiler: {sample:?}"
        );
        assert!(
            !sample.optimization.trim().is_empty(),
            "missing optimization provenance: {sample:?}"
        );
        assert!(
            Path::new(sample.path).is_file(),
            "provenance lane has no committed binary: {sample:?}"
        );
    }
    assert_eq!(
        paths.len(),
        10,
        "census lane inventory changed without review"
    );
}

/// Every architecture the LLIR decompiler claims must have a real corpus
/// denominator. A zero row is not a good score: it means the census measured
/// nothing and therefore cannot detect a coverage regression for that target.
#[test]
fn every_lifted_architecture_has_a_nonempty_census_denominator() {
    for arch in [Arch::X86, Arch::X86_64, Arch::ARM, Arch::AArch64] {
        let (census, files, functions) = corpus_census_for_arch(arch);
        assert!(files > 0, "{arch:?} has no committed census sample");
        assert!(functions > 0, "{arch:?} lifted no census function");
        assert!(
            census.instructions > 0,
            "{arch:?} produced no census instructions"
        );
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpaqueExemption {
    target: String,
    mnemonic_or_family: String,
    observed_count: usize,
    reason: String,
    semantic_risk: String,
    owner: String,
    removal_condition: String,
}

fn exemption_arch(target: &str) -> Option<Arch> {
    match target {
        "i386" => Some(Arch::X86),
        "x86_64" => Some(Arch::X86_64),
        "armv7" => Some(Arch::ARM),
        "aarch64" => Some(Arch::AArch64),
        _ => None,
    }
}

fn exemption_matches(pattern: &str, mnemonic: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or(pattern == mnemonic, |prefix| mnemonic.starts_with(prefix))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodedLiftExemption {
    target: String,
    mnemonic_or_family: String,
    observed_count: usize,
    reason: String,
    semantic_risk: String,
    owner: String,
    removal_condition: String,
}

fn decoded_function_coverage(
    data: &[u8],
    function: &crate::core::function::Function,
    arch: Arch,
    lifted: &LlirFunction,
) -> (BTreeMap<String, usize>, usize) {
    let modelled_vas: BTreeSet<u64> = lifted
        .blocks
        .iter()
        .flat_map(|block| block.instrs.iter())
        .filter(|instruction| {
            !matches!(
                &instruction.op,
                Op::Intrinsic {
                    ins,
                    outs,
                    reads_mem: true,
                    writes_mem: true,
                    ..
                } if ins.is_empty() && outs.is_empty()
            )
        })
        .map(|instruction| instruction.va)
        .collect();
    let disasm_arch: crate::core::disassembler::Architecture = arch.into();
    let mut backend = registry::for_arch(disasm_arch, Endianness::Little)
        .expect("lifted architecture must have a decoder");
    backend
        .set_thumb_mode(function.flags & FunctionFlags::IS_THUMB)
        .expect("validated ARM mode must be selectable");
    let mut missing = BTreeMap::new();
    let mut decoded = 0usize;

    for block in &lifted.blocks {
        let start = block.start_va;
        let end = block.end_va;
        let Some(file_offset) = va_to_code_file_offset(data, start) else {
            continue;
        };
        let available = data.len().saturating_sub(file_offset);
        let block_len = usize::try_from(end.saturating_sub(start))
            .unwrap_or(usize::MAX)
            .min(available);
        let bytes = &data[file_offset..file_offset + block_len];
        let mut offset = 0usize;
        while offset < bytes.len() {
            let va = start + offset as u64;
            let address = Address::new(AddressKind::VA, va, disasm_arch.address_bits(), None, None)
                .expect("valid decoded instruction address");
            let Ok(instruction) = backend.disassemble_instruction(&address, &bytes[offset..])
            else {
                break;
            };
            decoded += 1;
            if !modelled_vas.contains(&va) {
                *missing.entry(instruction.mnemonic.clone()).or_default() += 1;
            }
            let length = usize::from(instruction.length);
            assert!(
                length > 0,
                "decoder returned a zero-length instruction at {va:#x}"
            );
            offset = offset.saturating_add(length);
        }
    }

    (missing, decoded)
}

/// Decode every discovered basic block independently of the LLIR lifter and
/// return decoded mnemonics for which that lifter emitted either no op or only
/// maximally opaque ops at the source address. This is deliberately
/// address-based: one machine instruction may expand into several LLIR ops;
/// it is modelled when at least one of them declares narrower semantics.
fn decoded_requiring_exemption(arch: Arch) -> (BTreeMap<String, usize>, usize) {
    let budgets = Budgets {
        max_functions: 96,
        max_blocks: 512,
        max_instructions: 60_000,
        timeout_ms: 4000,
        total_timeout_ms: 0,
    };
    let mut missing = BTreeMap::new();
    let mut decoded = 0usize;

    for sample in CORPUS {
        if sample.arch != arch {
            continue;
        }
        let data = std::fs::read(sample.path).expect("read census sample");
        let (functions, _) = analyze_functions_bytes(&data, &budgets);
        for function in &functions {
            let Ok(lifted) = lift_function_from_bytes(&data, function, arch) else {
                continue;
            };
            let (function_missing, function_decoded) =
                decoded_function_coverage(&data, function, arch, &lifted);
            decoded += function_decoded;
            for (mnemonic, count) in function_missing {
                *missing.entry(mnemonic).or_default() += count;
            }
        }
    }

    (missing, decoded)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct LaneMeasurement {
    files: usize,
    functions: usize,
    decoded: usize,
    opaque: usize,
    intrinsics: usize,
}

fn target_lane_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X86 => "i386",
        Arch::X86_64 => "x86_64",
        Arch::ARM => "armv7",
        Arch::AArch64 => "aarch64",
        _ => panic!("unsupported census architecture: {arch:?}"),
    }
}

fn instruction_mode_name(arch: Arch, flags: FunctionFlags) -> &'static str {
    match arch {
        Arch::X86 => "x86-32",
        Arch::X86_64 => "x86-64",
        Arch::AArch64 => "aarch64",
        Arch::ARM if flags & FunctionFlags::IS_THUMB => "thumb",
        Arch::ARM => "a32",
        _ => panic!("unsupported census architecture: {arch:?}"),
    }
}

fn measured_lanes() -> BTreeMap<String, LaneMeasurement> {
    let budgets = Budgets {
        max_functions: 96,
        max_blocks: 512,
        max_instructions: 60_000,
        timeout_ms: 4000,
        total_timeout_ms: 0,
    };
    let mut lanes = BTreeMap::<String, LaneMeasurement>::new();

    for sample in CORPUS {
        let data = std::fs::read(sample.path).expect("read census lane sample");
        let (functions, _) = analyze_functions_bytes(&data, &budgets);
        let mut file_lanes = BTreeSet::new();
        for function in &functions {
            let Ok(lifted) = lift_function_from_bytes(&data, function, sample.arch) else {
                continue;
            };
            let key = format!(
                "{}/{}/{}/{}",
                target_lane_name(sample.arch),
                instruction_mode_name(sample.arch, function.flags),
                sample.compiler,
                sample.optimization
            );
            let (_, decoded) = decoded_function_coverage(&data, function, sample.arch, &lifted);
            let mut effects = EffectCensus::default();
            census_into(&lifted, &mut effects);
            let lane = lanes.entry(key.clone()).or_default();
            lane.functions += 1;
            lane.decoded += decoded;
            lane.opaque += effects.opaque();
            lane.intrinsics +=
                effects.opaque() + effects.modelled_intrinsic.values().sum::<usize>();
            file_lanes.insert(key);
        }
        for key in file_lanes {
            lanes.get_mut(&key).expect("function created lane").files += 1;
        }
    }
    lanes
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaneBaseline {
    key: String,
    minimum_files: usize,
    minimum_functions: usize,
    minimum_decoded: usize,
    maximum_opaque: usize,
    maximum_intrinsics: usize,
}

#[test]
fn every_provenance_lane_has_a_ratchet() {
    let baselines: Vec<LaneBaseline> = serde_json::from_str(include_str!(
        "../../tests/decompiler_fixtures/effect_census_lane_baseline.json"
    ))
    .expect("parse effect census lane baseline");
    let measured = measured_lanes();
    let baseline_keys: BTreeSet<_> = baselines.iter().map(|row| row.key.as_str()).collect();
    let measured_keys: BTreeSet<_> = measured.keys().map(String::as_str).collect();
    assert_eq!(
        baseline_keys, measured_keys,
        "census lane set changed; measured={measured:#?}"
    );
    for baseline in baselines {
        let current = measured[&baseline.key];
        assert!(
            current.files >= baseline.minimum_files,
            "{} lost a file denominator: {current:?}",
            baseline.key
        );
        assert!(
            current.functions >= baseline.minimum_functions,
            "{} lost function coverage: {current:?}",
            baseline.key
        );
        assert!(
            current.decoded >= baseline.minimum_decoded,
            "{} lost decoded coverage: {current:?}",
            baseline.key
        );
        assert!(
            current.opaque <= baseline.maximum_opaque,
            "{} gained opaque instructions: {current:?}",
            baseline.key
        );
        assert!(
            current.intrinsics <= baseline.maximum_intrinsics,
            "{} gained generic intrinsics: {current:?}",
            baseline.key
        );
    }
}

/// A decoded machine instruction must either produce at least one LLIR op at
/// its source address or appear in the reviewed silent-lift manifest. Opaque
/// LLIR is governed separately; this gate catches instructions that disappear
/// before the effect census can see them at all.
#[test]
fn every_decoded_instruction_reaches_llir_or_has_a_reviewed_exemption() {
    let exemptions: Vec<DecodedLiftExemption> = serde_json::from_str(include_str!(
        "../../tests/decompiler_fixtures/decoded_lift_exemptions.json"
    ))
    .expect("parse reviewed decoded-to-LLIR exemptions");
    let census = [
        ("i386", Arch::X86),
        ("x86_64", Arch::X86_64),
        ("armv7", Arch::ARM),
        ("aarch64", Arch::AArch64),
    ]
    .map(|(target, arch)| {
        let (missing, decoded) = decoded_requiring_exemption(arch);
        (target, arch, missing, decoded)
    });
    let mut covered = BTreeSet::new();

    for exemption in &exemptions {
        let arch = exemption_arch(&exemption.target)
            .unwrap_or_else(|| panic!("unknown exemption target: {}", exemption.target));
        assert!(
            exemption.observed_count > 0,
            "zero-count exemption is stale"
        );
        for (field, value) in [
            ("reason", &exemption.reason),
            ("semantic_risk", &exemption.semantic_risk),
            ("owner", &exemption.owner),
            ("removal_condition", &exemption.removal_condition),
        ] {
            assert!(!value.trim().is_empty(), "empty {field}: {exemption:?}");
        }
        let (_, _, missing, decoded) = census
            .iter()
            .find(|(_, census_arch, _, _)| *census_arch == arch)
            .expect("recognized target must have a census row");
        assert!(
            *decoded > 0,
            "{} has no decoded denominator",
            exemption.target
        );
        let observed: usize = missing
            .iter()
            .filter(|(mnemonic, _)| exemption_matches(&exemption.mnemonic_or_family, mnemonic))
            .map(|(mnemonic, count)| {
                assert!(
                    covered.insert((exemption.target.clone(), mnemonic.clone())),
                    "decoded mnemonic {mnemonic} matched more than one exemption"
                );
                *count
            })
            .sum();
        assert!(observed > 0, "exemption no longer fires: {exemption:?}");
        assert!(
            observed <= exemption.observed_count,
            "silent-lift count grew from {} to {observed}: {exemption:?}",
            exemption.observed_count
        );
    }

    let mut unreviewed = BTreeMap::new();
    for (target, _arch, missing, decoded) in census {
        assert!(decoded > 0, "{target} has no decoded denominator");
        for mnemonic in missing.keys() {
            if !covered.contains(&(target.to_string(), mnemonic.clone())) {
                unreviewed
                    .entry(target.to_string())
                    .or_insert_with(BTreeMap::new)
                    .insert(mnemonic.clone(), missing[mnemonic]);
            }
        }
    }
    assert!(
        unreviewed.is_empty(),
        "decoded instructions reached no modelled LLIR op: {unreviewed:#?}"
    );
}

#[test]
fn every_opaque_census_entry_has_one_live_reviewed_exemption() {
    let exemptions: Vec<OpaqueExemption> = serde_json::from_str(include_str!(
        "../../tests/decompiler_fixtures/effect_census_exemptions.json"
    ))
    .expect("parse reviewed opaque-effect exemptions");

    let mut covered = std::collections::BTreeSet::new();
    for exemption in &exemptions {
        let arch = exemption_arch(&exemption.target)
            .unwrap_or_else(|| panic!("unknown exemption target: {}", exemption.target));
        assert!(
            exemption.observed_count > 0,
            "zero-count exemption is stale"
        );
        for (field, value) in [
            ("reason", &exemption.reason),
            ("semantic_risk", &exemption.semantic_risk),
            ("owner", &exemption.owner),
            ("removal_condition", &exemption.removal_condition),
        ] {
            assert!(!value.trim().is_empty(), "empty {field}: {exemption:?}");
        }

        let (census, _, _) = corpus_census_for_arch(arch);
        let observed: usize = census
            .opaque_intrinsic
            .iter()
            .filter(|(mnemonic, _)| exemption_matches(&exemption.mnemonic_or_family, mnemonic))
            .map(|(mnemonic, count)| {
                assert!(
                    covered.insert((exemption.target.clone(), mnemonic.clone())),
                    "opaque mnemonic {mnemonic} matched more than one exemption"
                );
                *count
            })
            .sum();
        assert!(observed > 0, "exemption no longer fires: {exemption:?}");
        assert!(
            observed <= exemption.observed_count,
            "opaque count grew from {} to {observed}: {exemption:?}",
            exemption.observed_count
        );
    }

    for (target, arch) in [
        ("i386", Arch::X86),
        ("x86_64", Arch::X86_64),
        ("armv7", Arch::ARM),
        ("aarch64", Arch::AArch64),
    ] {
        let (census, _, _) = corpus_census_for_arch(arch);
        for mnemonic in census.opaque_intrinsic.keys() {
            assert!(
                covered.contains(&(target.to_string(), mnemonic.clone())),
                "unreviewed opaque effect on {target}: {mnemonic}"
            );
        }
    }
}

/// Nothing that reaches a dataflow consumer may declare *no* footprint.
///
/// `Op::Unknown` is the only op with that property, and `lift_function` lowers
/// every one the per-arch lifters emit into an opaque `Op::Intrinsic` before
/// returning. This is the corpus-scale form of that claim: if a lifter ever
/// grows a path around `lower_unknowns`, this is what notices.
#[test]
fn no_lifted_instruction_in_the_corpus_declares_no_footprint() {
    let (total, files, functions) = corpus_census();
    assert!(files >= 3, "corpus too small to mean anything: {files}");
    assert!(functions > 50, "too few functions lifted: {functions}");
    assert_eq!(
        total.residual_unknown,
        Default::default(),
        "residual Op::Unknown reached a consumer"
    );
}

/// A call that reaches a dataflow consumer with no declared footprint is a
/// call `use_def` reports as defining nothing and using nothing — design rule
/// 5's "unknown means no effect", which the rule forbids.
///
/// Raw `lift_function_from_bytes` output is exactly that state for almost every
/// call: the ABI pass is a separate, later step. The only calls that leave the
/// lifter with anything attached are CFG-proven tail calls, and what they carry
/// is a *placeholder* — `is_tail_call` set, no argument, no result — which is
/// the same empty footprint under a different shape.
///
/// So this test measures the window rather than pretending it is not there, and
/// pins the fact that `abi::annotate_calls` closes it for every call including
/// the placeholders.
#[test]
fn every_raw_lifted_call_is_closed_by_the_abi_pass() {
    let (raw, _files, _functions) = corpus_census();
    assert_eq!(
        raw.calls_with_effects, 0,
        "a raw lift declared a real footprint; the ABI pass is supposed to be separate"
    );
    assert!(
        raw.calls_without_effects > 0 && raw.calls_with_placeholder_effects > 0,
        "corpus exercises neither call shape, so this measures nothing"
    );

    let budgets = Budgets {
        max_functions: 32,
        max_blocks: 256,
        max_instructions: 20_000,
        timeout_ms: 4000,
        total_timeout_ms: 0,
    };
    let path =
        Path::new("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2");
    assert!(path.exists(), "sample corpus is missing");
    let data = std::fs::read(path).expect("read sample");
    let (discovered, _call_graph) = analyze_functions_bytes(&data, &budgets);
    let mut annotated = EffectCensus::default();
    for function in &discovered {
        if let Ok(mut lifted) = lift_function_from_bytes(&data, function, Arch::X86_64) {
            crate::ir::abi::annotate_calls(&mut lifted, crate::ir::call_args::CallConv::SysVAmd64);
            census_into(&lifted, &mut annotated);
        }
    }
    assert_eq!(
        annotated.undeclared(),
        0,
        "abi::annotate_calls left {} call(s) with no declared footprint \
         ({} none, {} placeholder)",
        annotated.undeclared(),
        annotated.calls_without_effects,
        annotated.calls_with_placeholder_effects,
    );
    assert!(annotated.calls_with_effects > 0);
}

/// No ARM32 *data-processing* mnemonic may reach a consumer as an opaque
/// intrinsic.
///
/// The per-ISA census caught this as a rate: ARM32 rendered 16 of its 242
/// lifted instructions — 6.6% — as an opaque `add`, against 0.18% on x86-64 and
/// 0% on AArch64, and every one of the 16 was the same mnemonic. They were the
/// A32 modified-immediate encoding capstone reports as a split
/// `#<imm8>, #<rotation>` pair, which no arity check in `lift_arm32` matched
/// (see `fold_modified_immediate`). An opaque intrinsic declares a maximal
/// footprint, so a register-plus-constant `add` was telling every dataflow
/// consumer that it read and wrote all memory.
///
/// This pins the repair by *category* rather than by count: a raw total would
/// move whenever an unrelated mnemonic gained or lost coverage, and would say
/// nothing about the thing that was wrong. Any of these names reappearing means
/// an encoding of a fully-modelled operation stopped being decoded.
#[test]
fn no_arm32_data_processing_mnemonic_is_opaque() {
    /// Mnemonics `lift_arm32` lowers exactly, so an opaque one is a decode gap.
    const MODELLED: &[&str] = &[
        "add", "adds", "addw", "sub", "subs", "subw", "and", "ands", "orr", "orrs", "eor", "eors",
        "mov", "movs", "movw", "cmp", "cmn", "mvn", "mvns", "lsl", "lsls", "lsr", "lsrs", "asr",
        "asrs", "mul", "muls", "rsb", "rsbs", "neg", "negs",
    ];

    let budgets = Budgets {
        max_functions: 96,
        max_blocks: 512,
        max_instructions: 60_000,
        timeout_ms: 4000,
        total_timeout_ms: 0,
    };
    let mut census = EffectCensus::default();
    let mut lifted_any = false;
    for sample in CORPUS {
        if sample.arch != Arch::ARM {
            continue;
        }
        let path = Path::new(sample.path);
        if !path.exists() {
            continue;
        }
        let data = std::fs::read(path).expect("read sample");
        let (discovered, _call_graph) = analyze_functions_bytes(&data, &budgets);
        for function in &discovered {
            if let Ok(lifted) = lift_function_from_bytes(&data, function, Arch::ARM) {
                census_into(&lifted, &mut census);
                lifted_any = true;
            }
        }
    }
    assert!(
        lifted_any,
        "no ARM32 sample lifted, so this measures nothing"
    );
    assert!(
        census.instructions > 100,
        "too little ARM32 code to mean anything: {}",
        census.instructions
    );
    let regressed: Vec<_> = census
        .opaque_intrinsic
        .iter()
        .filter(|(name, _)| MODELLED.contains(&name.as_str()))
        .collect();
    assert!(
        regressed.is_empty(),
        "ARM32 lowers these exactly, yet they reached a consumer as opaque \
         intrinsics declaring a maximal footprint: {regressed:?} \
         (of {} instructions, {} opaque overall)",
        census.instructions,
        census.opaque(),
    );
}

/// Print the histogram the two tests above only summarise, per architecture.
///
/// The per-ISA split is the part that turns the report into a work queue: a
/// mnemonic that is opaque on one architecture and modelled on another names a
/// specific lifter gap rather than a general one.
#[test]
#[ignore = "reporting, not checking: prints the census"]
fn report_effect_census() {
    println!("provenance lanes:");
    for (key, measured) in measured_lanes() {
        println!("  {key}: {measured:?}");
    }
    for arch in [Arch::X86, Arch::X86_64, Arch::AArch64, Arch::ARM] {
        let (per_arch, files, functions) = corpus_census_for_arch(arch);
        let (decoded_opaque, decoded) = decoded_requiring_exemption(arch);
        println!(
            "{arch:?}: files={files} functions={functions} instrs={} opaque={} decoded={decoded} decoded_opaque={} {:?}",
            per_arch.instructions,
            per_arch.opaque(),
            decoded_opaque.values().sum::<usize>(),
            per_arch.opaque_intrinsic
        );
        println!("  decoded opaque: {decoded_opaque:?}");
    }
    let (total, files, functions) = corpus_census();
    println!(
        "files={files} functions={functions} instructions={}",
        total.instructions
    );
    println!(
        "calls: with_effects={} placeholder={} without_effects={}",
        total.calls_with_effects, total.calls_with_placeholder_effects, total.calls_without_effects
    );
    println!("residual Op::Unknown = {}", total.residual_unknown.len());
    for (name, count) in &total.residual_unknown {
        println!("  unknown {name:>16} {count}");
    }
    let mut opaque: Vec<_> = total.opaque_intrinsic.iter().collect();
    opaque.sort_by_key(|(name, count)| (std::cmp::Reverse(**count), (*name).clone()));
    println!(
        "opaque intrinsics = {} over {} names",
        total.opaque(),
        opaque.len()
    );
    for (name, count) in opaque.iter().take(40) {
        println!("  opaque  {name:>16} {count}");
    }
    let mut modelled: Vec<_> = total.modelled_intrinsic.iter().collect();
    modelled.sort_by_key(|(name, count)| (std::cmp::Reverse(**count), (*name).clone()));
    println!(
        "modelled intrinsics = {} over {} names",
        modelled.iter().map(|(_, c)| **c).sum::<usize>(),
        modelled.len()
    );
    for (name, count) in modelled.iter().take(40) {
        println!("  modelled {name:>16} {count}");
    }
}
