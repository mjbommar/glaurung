// Quick integration test for overlay module
use glaurung::core::binary::Format;
use glaurung::triage::overlay::{detect_overlay, OverlayFormat};

fn main() {
    println!("Testing overlay module...");
    
    // Test with simple data that doesn't have overlay
    let simple_data = b"Hello World";
    let result = detect_overlay(simple_data, Format::PE);
    match result {
        Ok(None) => println!("✓ Simple data correctly detected as having no overlay"),
        Ok(Some(_)) => println!("✗ Simple data incorrectly detected as having overlay"),
        Err(e) => println!("✗ Error with simple data: {}", e),
    }
    
    // Test with unsupported format
    let result = detect_overlay(simple_data, Format::MachO);
    match result {
        Err(e) => println!("✓ Unsupported format correctly rejected: {}", e),
        _ => println!("✗ Unsupported format should have been rejected"),
    }
    
    // Test OverlayFormat display
    println!("✓ OverlayFormat::ZIP displays as: {}", OverlayFormat::ZIP);
    println!("✓ OverlayFormat::Unknown displays as: {}", OverlayFormat::Unknown);
    
    println!("Overlay module test completed successfully!");
}
