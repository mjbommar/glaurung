// Test program to verify improved IOC classifier
use glaurung::strings::{extract_summary, StringsConfig};
use std::fs;

fn main() {
    let path = "samples/binaries/platforms/windows/amd64/export/windows/dotnet/mono/Hello-mono.exe";

    // Read the binary file
    let data = fs::read(path).expect("Failed to read file");

    // Create config using defaults
    let config = StringsConfig::default();

    // Extract strings and IOCs
    let summary = extract_summary(&data, &config);

    println!("=== Improved Classifier Results ===");
    println!("Strings found:");
    println!("  ASCII: {}", summary.ascii_count);
    println!("  UTF-16LE: {}", summary.utf16le_count);

    if let Some(ioc_counts) = &summary.ioc_counts {
        println!("\nIOCs detected:");
        for (kind, count) in ioc_counts {
            if *count > 0 {
                println!("  {}: {}", kind, count);
            }
        }
    } else {
        println!("\nNo IOCs detected (good - no false positives!)");
    }

    // Now test with classification disabled
    let mut config_old = StringsConfig::default();
    config_old.enable_classification = false;

    let summary_old = extract_summary(&data, &config_old);

    println!("\n=== Original Classifier Results ===");
    if let Some(ioc_counts) = &summary_old.ioc_counts {
        println!("IOCs detected:");
        for (kind, count) in ioc_counts {
            if *count > 0 {
                println!("  {}: {}", kind, count);
            }
        }
    }

    println!("\n=== Comparison ===");
    let old_ipv4 = summary_old
        .ioc_counts
        .as_ref()
        .and_then(|m| m.get("ipv4"))
        .cloned()
        .unwrap_or(0);
    let new_ipv4 = summary
        .ioc_counts
        .as_ref()
        .and_then(|m| m.get("ipv4"))
        .cloned()
        .unwrap_or(0);

    println!(
        "IPv4 false positives eliminated: {} -> {}",
        old_ipv4, new_ipv4
    );

    if new_ipv4 == 0 && old_ipv4 > 0 {
        println!("✅ Success! Improved classifier eliminated false positive IPv4 detections!");
    }
}
