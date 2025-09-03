use crate::common::test_utils::create_temp_file_with_size;
use glaurung::core::triage::TriageErrorKind;
use glaurung::triage::api::{analyze_bytes, analyze_path};
use glaurung::triage::io::IOLimits;

#[test]
fn budget_exceeded_error_is_recorded_for_bytes() {
    // 512 KiB input, but cap reads to 4 KiB
    let data = vec![0x41u8; 512 * 1024];
    let limits = IOLimits {
        max_read_bytes: 4 * 1024,
        max_file_size: u64::MAX,
    };
    let art = analyze_bytes(&data, &limits).expect("analyze_bytes");
    // Budgets present and limit hit
    let b = art.budgets.as_ref().expect("budgets present");
    assert!(b.hit_byte_limit, "expected hit_byte_limit true");
    // Error taxonomy should include BudgetExceeded
    let errs = art.errors.unwrap_or_default();
    assert!(errs
        .iter()
        .any(|e| e.kind == TriageErrorKind::BudgetExceeded));
}

#[test]
fn budget_exceeded_error_is_recorded_for_path() {
    // Create a 1 MiB temp file and cap reads to 4 KiB
    let tf = create_temp_file_with_size(1024 * 1024, 0x00);
    let limits = IOLimits {
        max_read_bytes: 4 * 1024,
        max_file_size: u64::MAX,
    };
    let art = analyze_path(tf.path(), &limits).expect("analyze_path");
    let b = art.budgets.as_ref().expect("budgets present");
    assert!(b.hit_byte_limit);
    let errs = art.errors.unwrap_or_default();
    assert!(errs
        .iter()
        .any(|e| e.kind == TriageErrorKind::BudgetExceeded));
}
