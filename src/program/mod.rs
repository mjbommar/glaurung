//! Program-scoped image, target, environment, and analysis ownership.

pub mod environment;
pub mod image;
pub mod session;

#[cfg(test)]
mod image_tests;
#[cfg(test)]
mod session_tests;
