use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use glaurung::triage::config::EntropyConfig;
use glaurung::triage::entropy::compute_entropy;
use std::fs;

fn bench_entropy(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy");
    let cfg = EntropyConfig::default();
    let paths = [
        // text-like (low entropy after header)
        "samples/containers/tar/hello-cpp-g++-O0.tar",
        // compressed/high-entropy
        "samples/containers/gzip/hello-cpp-g++-O0.gz",
    ];
    for p in paths {
        if let Ok(data) = fs::read(p) {
            group.throughput(Throughput::Bytes(data.len() as u64));
            group.bench_function(p, |b| b.iter(|| compute_entropy(&data, &cfg)));
        }
    }
    group.finish();
}

criterion_group!(benches, bench_entropy);
criterion_main!(benches);
