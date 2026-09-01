//! Every demangler, on arbitrary text.
//!
//! `src/demangle/` has ONE unit test for three grammars (Itanium, Rust v0,
//! MSVC). Demanglers are a classic panic farm: recursive-descent parsers over
//! attacker-supplied strings, reached straight from a symbol table nobody
//! validated. The property here is only that they terminate and do not panic;
//! what they return on garbage is not this target's business.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Long inputs are the interesting ones for recursion depth, but an
    // unbounded one only measures the allocator.
    if text.len() > 4096 {
        return;
    }
    let _ = glaurung::demangle::detect_flavor(text);
    let _ = glaurung::demangle::demangle_one(text);
});
