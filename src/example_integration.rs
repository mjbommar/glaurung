//! Integration example showing how to use logging, error handling, and timeouts together.
//!
//! This module demonstrates best practices for using the new infrastructure.

use crate::error::{AnalysisBudget, GlaurungError, Result};
use crate::logging::init_tracing;
use crate::timeout::{with_timeout, IterationTimeout, TimeoutConfig};
use std::time::Duration;
use tracing::{error, info, warn};

/// Example function that demonstrates proper error handling
fn parse_binary_with_validation(data: &[u8]) -> Result<()> {
    // Validate input
    if data.is_empty() {
        return Err(GlaurungError::InvalidInput(
            "Binary data is empty".to_string(),
        ));
    }

    if data.len() > 1024 * 1024 * 100 {
        // 100MB limit
        return Err(GlaurungError::ResourceExhausted {
            resource: "memory".to_string(),
            used: data.len(),
            limit: 1024 * 1024 * 100,
        });
    }

    // Check magic bytes
    if data.len() < 4 {
        return Err(GlaurungError::InvalidFormat(
            "File too small for magic bytes".to_string(),
        ));
    }

    info!("Binary validation passed, size: {} bytes", data.len());
    Ok(())
}

/// Example async function with timeout
async fn analyze_with_timeout(data: Vec<u8>) -> Result<String> {
    let config = TimeoutConfig::new(30, "binary_analysis");

    with_timeout(config, async move {
        // Simulate some async work
        tokio::time::sleep(Duration::from_millis(100)).await;

        parse_binary_with_validation(&data)?;

        Ok("Analysis complete".to_string())
    })
    .await
}

/// Example function with iteration timeout
fn process_instructions_with_timeout(instruction_count: usize) -> Result<usize> {
    let mut timeout = IterationTimeout::new(5, "instruction_processing").with_check_interval(100);

    let mut processed = 0;

    for i in 0..instruction_count {
        // Check timeout every iteration (controlled by check_interval)
        timeout.check()?;

        // Simulate instruction processing
        std::thread::sleep(Duration::from_micros(10));
        processed += 1;

        if i % 1000 == 0 {
            info!("Processed {} instructions", i);
        }
    }

    info!(
        "Completed processing {} instructions in {:?}",
        processed,
        timeout.elapsed()
    );

    Ok(processed)
}

/// Example showing budget enforcement
fn analyze_with_budget(data: &[u8], budget: &AnalysisBudget) -> Result<()> {
    info!("Starting analysis with budget: {}", budget);

    // Check memory budget
    let memory_usage_mb = data.len() / (1024 * 1024);
    if memory_usage_mb > budget.max_memory_mb {
        return Err(GlaurungError::ResourceExhausted {
            resource: "memory".to_string(),
            used: memory_usage_mb,
            limit: budget.max_memory_mb,
        });
    }

    // Use iteration timeout for time budget
    let mut timeout = IterationTimeout::new(budget.max_time_seconds, "budget_analysis");

    // Simulate processing with budget checks
    for i in 0..budget.max_instructions {
        timeout.check()?;

        if i > budget.max_instructions {
            return Err(GlaurungError::ResourceExhausted {
                resource: "instructions".to_string(),
                used: i,
                limit: budget.max_instructions,
            });
        }
    }

    Ok(())
}

/// Example showing proper error logging and propagation
fn comprehensive_analysis_example() -> Result<()> {
    // Initialize tracing
    init_tracing();

    info!("Starting comprehensive analysis example");

    // Example 1: Input validation with proper error handling
    let test_data = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
    match parse_binary_with_validation(&test_data) {
        Ok(()) => info!("Validation successful"),
        Err(e) => {
            error!("Validation failed: {}", e);
            return Err(e);
        }
    }

    // Example 2: Processing with timeout
    match process_instructions_with_timeout(1000) {
        Ok(count) => info!("Processed {} instructions", count),
        Err(GlaurungError::Timeout { seconds }) => {
            warn!("Processing timed out after {} seconds", seconds);
        }
        Err(e) => {
            error!("Processing failed: {}", e);
            return Err(e);
        }
    }

    // Example 3: Budget enforcement
    let budget = AnalysisBudget::default();
    if let Err(e) = analyze_with_budget(&test_data, &budget) {
        match e {
            GlaurungError::ResourceExhausted {
                resource,
                used,
                limit,
            } => {
                warn!("Resource exhausted: {} ({}/{})", resource, used, limit);
            }
            _ => {
                error!("Budget analysis failed: {}", e);
                return Err(e);
            }
        }
    }

    info!("Comprehensive analysis example completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_empty_input() {
        init_tracing();
        let result = parse_binary_with_validation(&[]);
        assert!(matches!(result, Err(GlaurungError::InvalidInput(_))));
    }

    #[test]
    fn test_validation_too_large() {
        init_tracing();
        let large_data = vec![0u8; 1024 * 1024 * 101]; // 101MB
        let result = parse_binary_with_validation(&large_data);
        assert!(matches!(
            result,
            Err(GlaurungError::ResourceExhausted { .. })
        ));
    }

    #[test]
    fn test_validation_success() {
        init_tracing();
        let data = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
        let result = parse_binary_with_validation(&data);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_async_timeout_success() {
        init_tracing();
        let data = vec![0x7f, 0x45, 0x4c, 0x46];
        let result = analyze_with_timeout(data).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_iteration_timeout_success() {
        init_tracing();
        // Small number should complete within timeout
        let result = process_instructions_with_timeout(100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_budget_enforcement() {
        init_tracing();
        let mut budget = AnalysisBudget::default();
        budget.max_memory_mb = 1; // Very small budget

        let data = vec![0u8; 1024 * 1024 * 2]; // 2MB
        let result = analyze_with_budget(&data, &budget);
        assert!(matches!(
            result,
            Err(GlaurungError::ResourceExhausted { .. })
        ));
    }

    #[test]
    fn test_comprehensive_example() {
        // This test shows the full integration
        let result = comprehensive_analysis_example();
        assert!(result.is_ok());
    }
}
