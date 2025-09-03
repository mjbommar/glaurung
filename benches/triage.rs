use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use std::fs;

use glaurung::core::triage::{Budgets, TriagedArtifact};
use glaurung::strings;
use glaurung::triage::config::EntropyConfig;
use glaurung::triage::entropy::analyze_entropy;
use glaurung::triage::headers;
use glaurung::triage::heuristics::{architecture, endianness};
use glaurung::triage::packers::detect_packers;
use glaurung::triage::parsers;
use glaurung::triage::recurse::RecursionEngine;
use glaurung::triage::score;
use glaurung::triage::sniffers::CombinedSniffer;

fn triage_bytes(path: &str, data: &[u8]) -> TriagedArtifact {
    let sniff_len = data
        .len()
        .min(glaurung::triage::io::MAX_SNIFF_SIZE as usize);
    let header_len = data
        .len()
        .min(glaurung::triage::io::MAX_HEADER_SIZE as usize);
    let ent_len = data
        .len()
        .min(glaurung::triage::io::MAX_ENTROPY_SIZE as usize);
    let sniff_buf = &data[..sniff_len];
    let header_buf = &data[..header_len];
    let heur_buf = &data[..ent_len];

    let sn = CombinedSniffer::sniff(sniff_buf, Some(std::path::Path::new(path)));
    let hdr = headers::validate(header_buf);
    let ecfg = EntropyConfig::default();
    let ea = analyze_entropy(heur_buf, &ecfg);
    let entropy = Some(ea.summary.clone());
    let strings = {
        let s = strings::extract_summary(heur_buf, &strings::StringsConfig::default());
        if s.ascii_count == 0 && s.utf16le_count == 0 && s.utf16be_count == 0 {
            None
        } else {
            Some(s)
        }
    };
    let containers = {
        let engine = RecursionEngine::default();
        let mut tmp_budget = Budgets::new(data.len() as u64, 0, 0);
        let v = engine.discover_children(heur_buf, &mut tmp_budget, 0);
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    };
    let packers = {
        let v = detect_packers(heur_buf);
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    };
    let parser_results = parsers::parse(heur_buf);
    let merged_errors = if sn.errors.is_empty() && hdr.errors.is_empty() {
        None
    } else {
        let mut e = sn.errors;
        e.extend(hdr.errors);
        Some(e)
    };
    let (e_guess, e_conf) = endianness::guess(heur_buf);
    let arch_guesses = architecture::infer(heur_buf);

    let prelim = TriagedArtifact::new(
        "bench".into(),
        path.into(),
        data.len() as u64,
        None,
        sn.hints,
        hdr.candidates,
        entropy,
        Some(ea),
        strings,
        None, // symbols
        packers,
        containers,
        None, // overlay
        if parser_results.is_empty() {
            None
        } else {
            Some(parser_results)
        },
        Some(Budgets::new(data.len() as u64, 0, 0)),
        merged_errors,
        Some((e_guess, e_conf)),
        Some(arch_guesses),
    );
    let ranked = score::score(&prelim);
    TriagedArtifact::new(
        prelim.id,
        prelim.path,
        prelim.size_bytes,
        prelim.sha256,
        prelim.hints,
        ranked,
        prelim.entropy,
        prelim.entropy_analysis,
        prelim.strings,
        prelim.symbols,
        prelim.packers,
        prelim.containers,
        prelim.overlay,
        prelim.parse_status,
        prelim.budgets,
        prelim.errors,
        prelim.heuristic_endianness,
        prelim.heuristic_arch,
    )
}

fn bench_triage_samples(c: &mut Criterion) {
    let mut group = c.benchmark_group("triage-samples");
    // Small representative set across categories
    let candidates = [
        // ELF (linux/arm64)
        "samples/binaries/platforms/linux/arm64/export/fortran/hello-gfortran-O0",
        // PE (windows mingw)
        "samples/binaries/platforms/windows/i386/export/windows/i686/O0/hello-c-mingw32-O0.exe",
        // ZIP container
        "samples/containers/zip/hello-cpp-g++-O0.zip",
        // GZIP container
        "samples/containers/gzip/hello-cpp-g++-O0.gz",
        // UPX-packed ELF
        "samples/packed/hello-rust-release.upx9",
    ];

    for path in candidates {
        if let Ok(data) = fs::read(path) {
            group.throughput(Throughput::Bytes(data.len() as u64));
            group.bench_function(path, |b| {
                b.iter_batched(
                    || data.clone(),
                    |buf| {
                        let _ = triage_bytes(path, &buf);
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_triage_samples);
criterion_main!(benches);
