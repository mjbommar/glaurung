//! Program-scoped image, target, environment, and analysis ownership.

mod caller_environment;
pub mod environment;
mod format_environment;
pub mod image;
pub mod session;

#[cfg(test)]
mod image_tests;
#[cfg(test)]
mod session_tests;
