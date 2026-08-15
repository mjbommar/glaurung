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

use std::path::Path;

use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
use crate::core::binary::Arch;
use crate::ir::effect_census::{census_into, EffectCensus};
use crate::ir::lift_function::lift_function_from_bytes;

/// A cross-section of the committed sample corpus: two ISAs, three languages,
/// hand-written assembly, and both optimisation extremes.
const CORPUS: &[(&str, Arch)] = &[
    (
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0",
        Arch::X86_64,
    ),
    (
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        Arch::X86_64,
    ),
    (
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/c2_demo-gcc-O2",
        Arch::X86_64,
    ),
    (
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2",
        Arch::X86_64,
    ),
    (
        "samples/binaries/platforms/linux/amd64/rust/hello-rust-release",
        Arch::X86_64,
    ),
    (
        "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc",
        Arch::AArch64,
    ),
    (
        "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-asm-arm64-as",
        Arch::AArch64,
    ),
    (
        "samples/binaries/platforms/linux/arm64/export/native/gcc/O1/hello-cpp-g++-O1",
        Arch::AArch64,
    ),
    (
        "samples/binaries/platforms/linux/arm64/export/cross/armhf/hello-armhf-gcc",
        Arch::ARM,
    ),
];

fn corpus_census() -> (EffectCensus, usize, usize) {
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
    for (relative, arch) in CORPUS {
        let path = Path::new(relative);
        if !path.exists() {
            continue;
        }
        files += 1;
        let data = std::fs::read(path).expect("read sample");
        let (discovered, _call_graph) = analyze_functions_bytes(&data, &budgets);
        for function in &discovered {
            if let Ok(lifted) = lift_function_from_bytes(&data, function, *arch) {
                census_into(&lifted, &mut total);
                functions += 1;
            }
        }
    }
    (total, files, functions)
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

/// Print the histogram the two tests above only summarise, per architecture.
///
/// The per-ISA split is the part that turns the report into a work queue: a
/// mnemonic that is opaque on one architecture and modelled on another names a
/// specific lifter gap rather than a general one.
#[test]
#[ignore = "reporting, not checking: prints the census"]
fn report_effect_census() {
    for arch in [Arch::X86_64, Arch::AArch64, Arch::ARM] {
        let mut per_arch = EffectCensus::default();
        let budgets = Budgets {
            max_functions: 96,
            max_blocks: 512,
            max_instructions: 60_000,
            timeout_ms: 4000,
            total_timeout_ms: 0,
        };
        for (relative, entry_arch) in CORPUS {
            if *entry_arch != arch {
                continue;
            }
            let path = Path::new(relative);
            if !path.exists() {
                continue;
            }
            let data = std::fs::read(path).expect("read sample");
            let (discovered, _call_graph) = analyze_functions_bytes(&data, &budgets);
            for function in &discovered {
                if let Ok(lifted) = lift_function_from_bytes(&data, function, arch) {
                    census_into(&lifted, &mut per_arch);
                }
            }
        }
        println!(
            "{arch:?}: instrs={} opaque={} {:?}",
            per_arch.instructions,
            per_arch.opaque(),
            per_arch.opaque_intrinsic
        );
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
