//! F-11 entry/exit flag derivation and F-12 singleton-funcend removal.
//!
//! Owned by stage S3. `mod.rs` currently derives both inline and
//! approximately; this module is where the rules Joern actually applies go,
//! and `mod.rs` will call into it once they are here.
