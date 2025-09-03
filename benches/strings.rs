use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use std::fs;

use glaurung::strings::{extract_summary, StringsConfig};

fn bench_strings_samples(c: &mut Criterion) {
    let mut group = c.benchmark_group("strings-samples");
    // Representative set across categories
    let candidates = [
        // ELF (linux/arm64)
        "samples/binaries/platforms/linux/arm64/export/fortran/hello-gfortran-O0",
        // PE (windows mingw)
        "samples/binaries/platforms/windows/i386/export/windows/i686/O0/hello-c-mingw32-O0.exe",
        // UPX-packed ELF
        "samples/packed/hello-rust-release.upx9",
        // ZIP container (not a binary, but strings extraction exercises bytes)
        "samples/containers/zip/hello-cpp-g++-O0.zip",
    ];

    let cfg = StringsConfig::default();
    for path in candidates {
        if let Ok(data) = fs::read(path) {
            group.throughput(Throughput::Bytes(data.len() as u64));
            group.bench_function(path, |b| {
                b.iter_batched(
                    || data.clone(),
                    |buf| {
                        let _ = extract_summary(&buf, &cfg);
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_strings_samples);
criterion_main!(benches);
