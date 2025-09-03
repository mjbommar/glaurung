//! Custom error types for the I/O module.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum IoError {
    #[error("File size of {found} bytes exceeds the maximum allowed size of {limit} bytes.")]
    FileTooLarge { limit: u64, found: u64 },

    #[error(
        "A read operation would exceed the total read limit of {limit} bytes. (already read: {current})"
    )]
    ReadLimitExceeded { limit: u64, current: u64 },

    #[error("An underlying I/O error occurred.")]
    StdIo(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, IoError>;
