//! F-9: Joern's expression-level node granularity.
//!
//! The single largest parity gap. Joern materializes an operator node for
//! `&&`, `||` and `?:` in addition to the fork the short-circuit lowering
//! creates, so `a && b` costs more nodes than a naive lowering produces.
//! Owned by stage S3.
