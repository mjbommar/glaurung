// Builder Pattern Example for TriagedArtifact
// This demonstrates how the new builder pattern makes construction more readable and maintainable.

use glaurung::core::triage::{TriagedArtifact, Budgets};

fn main() {
    // OLD WAY: Using the constructor with 17 parameters (still works for backwards compatibility)
    let artifact_old = TriagedArtifact::new(
        "artifact-id-1".to_string(),     // id
        "/path/to/file.exe".to_string(),  // path
        2048,                            // size_bytes
        Some("abc123".to_string()),      // sha256
        vec![],                          // hints
        vec![],                          // verdicts
        None,                            // entropy
        None,                            // entropy_analysis
        None,                            // strings
        None,                            // symbols
        None,                            // packers
        None,                            // containers
        None,                            // overlay
        None,                            // parse_status
        Some(Budgets::new(2048, 100, 1)), // budgets
        None,                            // errors
        None,                            // heuristic_endianness
        None,                            // heuristic_arch
    );

    println!("Old way artifact ID: {}", artifact_old.id);

    // NEW WAY: Using the builder pattern - much more readable and maintainable!
    let artifact_new = TriagedArtifact::builder()
        .with_id("artifact-id-2")
        .with_path("/path/to/file.exe")
        .with_size_bytes(2048)
        .with_sha256_str("abc123")
        .with_budgets(Some(Budgets::new(2048, 100, 1)))
        .build()
        .expect("All required fields provided");

    println!("New way artifact ID: {}", artifact_new.id);

    // BENEFITS:
    // 1. Only specify fields you need
    // 2. Method names make it clear what each field represents
    // 3. Easy to add/remove fields without affecting other parameters
    // 4. Self-documenting code
    // 5. Compile-time validation of required fields

    // Example with minimal required fields only:
    let minimal_artifact = TriagedArtifact::builder()
        .with_id("minimal-id")
        .with_path("/minimal/path")
        .with_size_bytes(1024)
        .build()
        .expect("Minimal artifact");

    println!("Minimal artifact created: {}", minimal_artifact.id);

    // Error handling example - missing required field
    let result = TriagedArtifact::builder()
        .with_id("incomplete-id")
        // Missing path and size_bytes!
        .build();

    match result {
        Ok(_) => println!("This shouldn't happen"),
        Err(e) => println!("Build failed as expected: {}", e),
    }
}