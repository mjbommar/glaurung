use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rayon::prelude::*;
use std::hint::black_box;

use glaurung::strings::detect::{
    detect_string_language_ensemble, detect_with_lingua, detect_with_whatlang,
};
use glaurung::strings::detect_fast::detect_language_fast;

fn short_samples() -> Vec<&'static str> {
    vec![
        // Short greetings / tokens (various scripts)
        "hello world",
        "hola mundo",
        "привет мир",
        "مرحبا",
        "你好",
        "こんにちは",
        "नमस्ते",
        // Noise / gibberish
        "Q5V2T9ZK3L1N8B7X0",
        "[];:/\\$<>()",
    ]
}

fn long_samples() -> Vec<&'static str> {
    vec![
        // English
        "This is a simple English sentence for testing and benchmarking of language detection performance.",
        // Spanish
        "Este es un texto de ejemplo en español para probar el rendimiento de la detección de idioma.",
        // Russian
        "Это простой русский текст для тестирования производительности определения языка.",
        // Arabic
        "هذه جملة عربية بسيطة لاختبار أداء اكتشاف اللغة.",
        // Chinese
        "这是一段用于测试语言检测性能的中文句子。",
        // Japanese
        "これは言語検出の性能をテストするための日本語の文章です。",
        // Hindi
        "यह भाषा पहचान के प्रदर्शन का परीक्षण करने के लिए एक सरल हिंदी वाक्य है।",
        // Noise / gibberish
        "a9$k2@p5#m8&q3^z7!x4*",
    ]
}

fn make_dataset(samples: &[&str], repeat: usize) -> Vec<String> {
    samples
        .iter()
        .cycle()
        .take(samples.len() * repeat)
        .map(|s| s.to_string())
        .collect()
}

fn bench_lang_detect_single(c: &mut Criterion) {
    // Prime lingua detector once to exclude model init from measurements
    let _ = detect_with_lingua("Priming the lingua detector with an English sentence.");

    let mut group = c.benchmark_group("lang-detect-single");

    // Short texts
    let short = short_samples();
    let short_ds = make_dataset(&short, 200); // ~1.8k strings
    group.throughput(Throughput::Elements(short_ds.len() as u64));
    group.bench_function("whatlang_short", |b| {
        b.iter_batched(
            || short_ds.clone(),
            |data| {
                for s in data.iter() {
                    black_box(detect_with_whatlang(s));
                }
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("lingua_short", |b| {
        b.iter_batched(
            || short_ds.clone(),
            |data| {
                for s in data.iter() {
                    black_box(detect_with_lingua(s));
                }
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("ensemble_short", |b| {
        b.iter_batched(
            || short_ds.clone(),
            |data| {
                for s in data.iter() {
                    black_box(detect_string_language_ensemble(s, 4, 0.5, 0.4));
                }
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("fast_short", |b| {
        b.iter_batched(
            || short_ds.clone(),
            |data| {
                for s in data.iter() {
                    black_box(detect_language_fast(s));
                }
            },
            BatchSize::SmallInput,
        )
    });

    // Long texts
    let long = long_samples();
    let long_ds = make_dataset(&long, 100); // ~800 strings
    group.throughput(Throughput::Elements(long_ds.len() as u64));
    group.bench_function("whatlang_long", |b| {
        b.iter_batched(
            || long_ds.clone(),
            |data| {
                for s in data.iter() {
                    black_box(detect_with_whatlang(s));
                }
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("lingua_long", |b| {
        b.iter_batched(
            || long_ds.clone(),
            |data| {
                for s in data.iter() {
                    black_box(detect_with_lingua(s));
                }
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("ensemble_long", |b| {
        b.iter_batched(
            || long_ds.clone(),
            |data| {
                for s in data.iter() {
                    black_box(detect_string_language_ensemble(s, 4, 0.5, 0.4));
                }
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("fast_long", |b| {
        b.iter_batched(
            || long_ds.clone(),
            |data| {
                for s in data.iter() {
                    black_box(detect_language_fast(s));
                }
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_lang_detect_batch(c: &mut Criterion) {
    // Prime lingua detector once to exclude model init from measurements
    let _ = detect_with_lingua("Priming the lingua detector with an English sentence.");

    let mut group = c.benchmark_group("lang-detect-batch");

    // Mixed dataset for batch tests
    let mixed_short = make_dataset(&short_samples(), 1000); // ~9k strings
    let mixed_long = make_dataset(&long_samples(), 200); // ~1.6k strings

    // Sequential vs parallel for ensemble on short set
    group.throughput(Throughput::Elements(mixed_short.len() as u64));
    group.bench_function("ensemble_seq_short", |b| {
        b.iter_batched(
            || mixed_short.clone(),
            |data| {
                let _out: Vec<_> = data
                    .iter()
                    .map(|s| detect_string_language_ensemble(s, 4, 0.5, 0.4))
                    .collect();
                black_box(_out);
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("ensemble_par_short", |b| {
        b.iter_batched(
            || mixed_short.clone(),
            |data| {
                let _out: Vec<_> = data
                    .par_iter()
                    .map(|s| detect_string_language_ensemble(s, 4, 0.5, 0.4))
                    .collect();
                black_box(_out);
            },
            BatchSize::SmallInput,
        )
    });

    // Sequential vs parallel for ensemble on long set
    group.throughput(Throughput::Elements(mixed_long.len() as u64));
    group.bench_function("ensemble_seq_long", |b| {
        b.iter_batched(
            || mixed_long.clone(),
            |data| {
                let _out: Vec<_> = data
                    .iter()
                    .map(|s| detect_string_language_ensemble(s, 4, 0.5, 0.4))
                    .collect();
                black_box(_out);
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("ensemble_par_long", |b| {
        b.iter_batched(
            || mixed_long.clone(),
            |data| {
                let _out: Vec<_> = data
                    .par_iter()
                    .map(|s| detect_string_language_ensemble(s, 4, 0.5, 0.4))
                    .collect();
                black_box(_out);
            },
            BatchSize::SmallInput,
        )
    });

    // Fast detector batch (short set)
    group.throughput(Throughput::Elements(mixed_short.len() as u64));
    group.bench_function("fast_seq_short", |b| {
        b.iter_batched(
            || mixed_short.clone(),
            |data| {
                let _out: Vec<_> = data.iter().map(|s| detect_language_fast(s)).collect();
                black_box(_out);
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("fast_par_short", |b| {
        b.iter_batched(
            || mixed_short.clone(),
            |data| {
                let _out: Vec<_> = data.par_iter().map(|s| detect_language_fast(s)).collect();
                black_box(_out);
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, bench_lang_detect_single, bench_lang_detect_batch);
criterion_main!(benches);
