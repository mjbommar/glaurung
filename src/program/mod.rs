//! Program-scoped image, target, environment, and analysis ownership.

pub mod call_graph;
mod caller_environment;
pub mod environment;
mod format_environment;
pub mod image;
pub mod references;
pub mod session;
pub mod spans;
pub mod symbols;
pub mod types;

#[cfg(test)]
mod call_graph_tests;
#[cfg(test)]
mod image_tests;
#[cfg(test)]
mod session_tests;
