//! F-16: per-translation-unit resolution.
//!
//! Lexicographic max on `(is_non_degenerate, node_count)`; the binary's own TU
//! wins, and cross-TU best-by-name is the fallback. Owned by stage S3.
