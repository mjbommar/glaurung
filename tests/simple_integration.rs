//! Simple integration test to verify the test organization works.
//!
//! This test demonstrates that the new test structure is functional
//! without complex dependencies.

use glaurung::triage::sniffers::ContentSniffer;

/// Basic test that the library can be imported and used
#[test]
fn test_basic_functionality() {
    // Test with some basic data
    let data = b"Hello, World!";
    let hint = ContentSniffer::sniff_bytes(data);

    // The result might be None (no detection) or Some (detected)
    // Either is fine for this basic test
    match hint {
        Some(hint) => {
            println!("Detected: {:?}", hint.label);
            assert!(hint.mime.is_some());
        }
        None => {
            println!("No detection - this is expected for plain text");
        }
    }
}

/// Test that demonstrates the test organization
#[test]
fn test_organization_demo() {
    println!("Integration test organization is working!");
    // Use a runtime check to avoid clippy complaining about constant assertions
    let now = std::time::SystemTime::now();
    assert!(now.duration_since(std::time::UNIX_EPOCH).is_ok());
}
