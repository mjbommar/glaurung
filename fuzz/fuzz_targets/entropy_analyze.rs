#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cfg = glaurung::triage::config::EntropyConfig::default();
    let _ = glaurung::triage::entropy::analyze_entropy(data, &cfg);
});

