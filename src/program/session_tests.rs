use std::process::Command;

use crate::analysis::cfg::Budgets;

use super::session::ProgramSession;

fn real_test_session() -> (ProgramSession, u64) {
    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let source = directory.path().join("session.c");
    let executable = directory.path().join("session");
    std::fs::write(
        &source,
        "__attribute__((noinline)) int session_target(int x) { return x + 1; }\n\
         int main(void) { return session_target(4); }\n",
    )
    .expect("write real C fixture");
    let output = Command::new("cc")
        .args(["-g", "-O0", "-o"])
        .arg(&executable)
        .arg(&source)
        .output()
        .expect("host C compiler is available");
    assert!(
        output.status.success(),
        "compile real session fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let session = ProgramSession::from_path(&executable).expect("fixture is a real object");
    let entry = session
        .image()
        .defined_text_symbol_address("session_target")
        .expect("fixture target symbol");
    (session, entry)
}

fn focused_budgets() -> Budgets {
    Budgets {
        max_functions: 1,
        max_blocks: 64,
        max_instructions: 4_096,
        timeout_ms: 5_000,
        total_timeout_ms: 0,
    }
}

#[test]
fn exact_discovery_is_reused_within_one_session() {
    let (session, entry) = real_test_session();

    let first = session.discover_functions(&focused_budgets(), &[entry]);
    let after_first = session.discovery_cache_stats();
    let second = session.discover_functions(&focused_budgets(), &[entry]);
    let after_second = session.discovery_cache_stats();

    assert!(
        !first.is_empty(),
        "the real test executable entry is discoverable"
    );
    assert_eq!(
        first
            .iter()
            .map(|function| function.entry_point.value)
            .collect::<Vec<_>>(),
        second
            .iter()
            .map(|function| function.entry_point.value)
            .collect::<Vec<_>>()
    );
    assert_eq!(after_first.misses, 1);
    assert_eq!(after_first.hits, 0);
    assert_eq!(after_second.misses, 1);
    assert_eq!(after_second.hits, 1);
    assert_eq!(after_second.evictions, 0);

    session.clear_caches();
    let cleared = session.discovery_cache_stats();
    assert_eq!(cleared.entries, 0);
    assert_eq!(cleared.hits, 0);
    assert_eq!(cleared.misses, 0);
    assert_eq!(cleared.evictions, 0);
}

#[test]
fn discovery_cache_key_includes_budgets_and_normalized_seeds() {
    let (session, entry) = real_test_session();
    let mut wider = focused_budgets();
    wider.max_blocks += 1;

    let _ = session.discover_functions(&focused_budgets(), &[entry, entry]);
    let _ = session.discover_functions(&focused_budgets(), &[entry]);
    let _ = session.discover_functions(&wider, &[entry]);

    let stats = session.discovery_cache_stats();
    assert_eq!(stats.hits, 1, "duplicate seeds normalize to the same key");
    assert_eq!(stats.misses, 2, "a budget change requires new discovery");
    assert_eq!(stats.entries, 2);
}
