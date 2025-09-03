#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let _ = glaurung::triage::sniffers::CombinedSniffer::sniff(data, Some(Path::new("<fuzz>")));
});

