use glaurung::triage::config::*;

#[test]
fn test_triage_config_creation() {
    let config = TriageConfig::default();

    // Test that all default configurations are properly initialized
    assert_eq!(config.io.max_sniff_size, 4096);
    assert_eq!(config.entropy.window_size, 8192);
    assert_eq!(config.heuristics.min_string_length, 4);
    assert_eq!(config.scoring.infer_weight, 0.15);
    assert_eq!(config.packers.scan_limit, 524288);
    assert_eq!(config.headers.base_confidence, 0.7);
    assert_eq!(config.parsers.python_bytecode_confidence, 0.9);
}

#[test]
fn test_entropy_thresholds_defaults() {
    let thresholds = EntropyThresholds::default();

    assert_eq!(thresholds.text, 3.0);
    assert_eq!(thresholds.code, 5.0);
    assert_eq!(thresholds.compressed, 7.0);
    assert_eq!(thresholds.encrypted, 7.8);
    assert_eq!(thresholds.cliff_delta, 1.0);
    assert_eq!(thresholds.low_header, 4.0);
    assert_eq!(thresholds.high_body, 7.0);
}

#[test]
fn test_entropy_weights_defaults() {
    let weights = EntropyWeights::default();

    assert_eq!(weights.header_body_mismatch, 0.6);
    assert_eq!(weights.cliff_detected, 0.2);
    assert_eq!(weights.high_entropy, 0.1);
    assert_eq!(weights.encrypted_random, 0.2);
}

#[test]
fn test_config_modification() {
    let mut config = IOConfig::default();

    // Test field modification
    config.max_sniff_size = 8192;
    config.max_file_size = 52428800; // 50MB

    assert_eq!(config.max_sniff_size, 8192);
    assert_eq!(config.max_file_size, 52428800);
}

#[test]
fn test_nested_config_access() {
    let mut config = TriageConfig::default();

    // Test nested modification
    config.entropy.window_size = 16384;
    config.entropy.thresholds.text = 2.5;
    config.scoring.infer_weight = 0.20;

    assert_eq!(config.entropy.window_size, 16384);
    assert_eq!(config.entropy.thresholds.text, 2.5);
    assert_eq!(config.scoring.infer_weight, 0.20);
}

#[cfg(feature = "python-ext")]
mod python_tests {
    use super::*;

    #[test]
    fn test_python_accessible_fields() {
        // This test verifies that our Python bindings would work
        // by checking that all the expected fields are accessible
        let config = TriageConfig::default();

        // Test that we can access nested configurations
        let _io_config = config.io.clone();
        let _entropy_config = config.entropy.clone();
        let _heuristics_config = config.heuristics.clone();
        let _scoring_config = config.scoring.clone();
        let _packers_config = config.packers.clone();
        let _headers_config = config.headers.clone();
        let _parsers_config = config.parsers.clone();

        // Test entropy sub-configurations
        let _thresholds = config.entropy.thresholds.clone();
        let _weights = config.entropy.weights.clone();
    }
}
