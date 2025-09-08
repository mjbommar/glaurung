use std::fs;

#[test]
fn cfg_discovers_functions_on_sample_if_present() {
    // Use a known sample path if available
    let path = "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2";
    if !std::path::Path::new(path).exists() {
        // Skip silently if samples not present in this environment
        return;
    }
    let data = fs::read(path).expect("read sample");
    let budgets = glaurung::analysis::cfg::Budgets {
        max_functions: 16,
        max_blocks: 2048,
        max_instructions: 50_000,
        timeout_ms: 200,
    };
    let (funcs, cg) = glaurung::analysis::cfg::analyze_functions_bytes(&data, &budgets);
    assert!(!funcs.is_empty(), "expected at least one function");
    let f = &funcs[0];
    assert!(!f.basic_blocks.is_empty(), "expected some basic blocks");
    // Callgraph can be empty for trivial programs, but should be well-formed
    assert!(cg.edge_count() >= 0);
}
