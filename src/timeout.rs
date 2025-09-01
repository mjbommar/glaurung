//! Timeout utilities for preventing infinite loops and resource exhaustion.
//!
//! This module provides timeout mechanisms for binary analysis operations
//! to ensure they complete within reasonable time bounds.

use crate::error::{GlaurungError, Result};
use std::future::Future;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// Default timeout duration in seconds
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 300; // 5 minutes

/// Fast operation timeout in seconds (for simple operations)
pub const FAST_TIMEOUT_SECONDS: u64 = 10;

/// Timeout configuration for analysis operations
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Maximum duration for the operation
    pub duration: Duration,
    /// Whether to log timeout warnings
    pub log_warnings: bool,
    /// Operation name for logging
    pub operation_name: String,
}

impl TimeoutConfig {
    /// Create a new timeout configuration
    pub fn new(seconds: u64, operation: impl Into<String>) -> Self {
        Self {
            duration: Duration::from_secs(seconds),
            log_warnings: true,
            operation_name: operation.into(),
        }
    }

    /// Create a fast timeout configuration (10 seconds)
    pub fn fast(operation: impl Into<String>) -> Self {
        Self::new(FAST_TIMEOUT_SECONDS, operation)
    }

    /// Create a default timeout configuration (5 minutes)
    pub fn default_timeout(operation: impl Into<String>) -> Self {
        Self::new(DEFAULT_TIMEOUT_SECONDS, operation)
    }
}

/// Execute an async operation with a timeout
pub async fn with_timeout<T, F>(config: TimeoutConfig, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    debug!(
        "Starting operation '{}' with timeout of {}s",
        config.operation_name,
        config.duration.as_secs()
    );

    match timeout(config.duration, future).await {
        Ok(result) => {
            debug!(
                "Operation '{}' completed successfully",
                config.operation_name
            );
            result
        }
        Err(_) => {
            let msg = format!(
                "Operation '{}' timed out after {}s",
                config.operation_name,
                config.duration.as_secs()
            );

            if config.log_warnings {
                error!("{}", msg);
            }

            Err(GlaurungError::Timeout {
                seconds: config.duration.as_secs(),
            })
        }
    }
}

/// Synchronous timeout check for loop iterations
pub struct IterationTimeout {
    start: std::time::Instant,
    max_duration: Duration,
    check_interval: usize,
    iteration_count: usize,
    operation_name: String,
}

impl IterationTimeout {
    /// Create a new iteration timeout checker
    pub fn new(seconds: u64, operation: impl Into<String>) -> Self {
        Self {
            start: std::time::Instant::now(),
            max_duration: Duration::from_secs(seconds),
            check_interval: 1000, // Check every 1000 iterations by default
            iteration_count: 0,
            operation_name: operation.into(),
        }
    }

    /// Set the check interval (how often to check for timeout)
    pub fn with_check_interval(mut self, interval: usize) -> Self {
        self.check_interval = interval;
        self
    }

    /// Check if timeout has been exceeded
    /// Should be called in loops to prevent infinite iteration
    pub fn check(&mut self) -> Result<()> {
        self.iteration_count += 1;

        // Only check elapsed time every N iterations for performance
        if self.iteration_count.is_multiple_of(self.check_interval) {
            let elapsed = self.start.elapsed();

            if elapsed > self.max_duration {
                error!(
                    "Operation '{}' timed out after {} iterations and {:?}",
                    self.operation_name, self.iteration_count, elapsed
                );

                return Err(GlaurungError::Timeout {
                    seconds: elapsed.as_secs(),
                });
            }

            // Warn if taking longer than expected
            if elapsed.as_secs() > 30
                && self
                    .iteration_count
                    .is_multiple_of(self.check_interval * 10)
            {
                warn!(
                    "Operation '{}' still running after {} iterations ({:?})",
                    self.operation_name, self.iteration_count, elapsed
                );
            }
        }

        Ok(())
    }

    /// Get the number of iterations processed
    pub fn iterations(&self) -> usize {
        self.iteration_count
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

/// Macro for adding timeout checks to loops
#[macro_export]
macro_rules! check_timeout {
    ($timeout:expr) => {
        $timeout.check()?
    };
    ($timeout:expr, $msg:expr) => {
        $timeout.check().map_err(|e| {
            tracing::error!("Timeout in {}: {}", $msg, e);
            e
        })?
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_async_timeout_success() {
        let config = TimeoutConfig::new(1, "test_operation");

        let result = with_timeout(config, async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(42)
        })
        .await;

        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_async_timeout_failure() {
        let config = TimeoutConfig::new(1, "test_operation");

        let result: Result<i32> = with_timeout(config, async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok(42)
        })
        .await;

        assert!(matches!(result, Err(GlaurungError::Timeout { .. })));
    }

    #[test]
    fn test_iteration_timeout() {
        let mut timeout = IterationTimeout::new(1, "test_loop").with_check_interval(10);

        // Should succeed for a reasonable number of iterations
        for _ in 0..100 {
            timeout.check().unwrap();
        }

        // Simulate long-running operation
        std::thread::sleep(Duration::from_secs(2));

        // Make sure we hit a check interval multiple (100 + 10 = 110)
        for _ in 0..10 {
            let result = timeout.check();
            if result.is_err() {
                assert!(matches!(result, Err(GlaurungError::Timeout { .. })));
                return;
            }
        }
        panic!("Expected timeout error");
    }

    #[test]
    fn test_iteration_counter() {
        let mut timeout = IterationTimeout::new(60, "test_counter").with_check_interval(1);

        for _ in 0..50 {
            timeout.check().unwrap();
        }

        assert_eq!(timeout.iterations(), 50);
    }
}
