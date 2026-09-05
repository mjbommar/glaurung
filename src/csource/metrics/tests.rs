//! Unit tests for the source metrics.
//!
//! Every expected number here is derived by hand from the source in the test,
//! not captured from a run: a golden value copied out of the implementation
//! tests that the implementation still does what it did, which is not the same
//! as testing that it is right.

use super::*;

/// Measure one function, by name, from a snippet.
fn one(text: &str, name: &str) -> FunctionMetrics {
    let report = analyze(text).into_parts().0;
    report
        .functions
        .into_iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no function named {name} in:\n{text}"))
}

#[test]
fn an_empty_function_is_a_straight_line() {
    let f = one("void f(void) {}", "f");
    // Entry -> Exit and nothing else: one edge, two nodes, so E - N + 2 = 1.
    assert_eq!(f.graph.cyclomatic, 1);
    assert_eq!(f.graph.decision_points, 0);
    assert_eq!(f.shape.cognitive, 0);
    assert_eq!(f.shape.max_nesting, 0);
    assert_eq!(f.parameters, 0, "`(void)` declares no parameters");
    assert!(f.has_body);
    assert_eq!(f.graph.unreachable_nodes, 0);
}

#[test]
fn one_if_is_one_decision() {
    let f = one("int f(int a) { if (a) { return 1; } return 0; }", "f");
    assert_eq!(f.graph.decision_points, 1);
    assert_eq!(f.graph.cyclomatic, 2);
    assert_eq!(f.shape.cognitive, 1, "+1 for the if, at nesting 0");
    assert_eq!(f.shape.max_nesting, 1, "the then-arm sits one level in");
    assert_eq!(f.parameters, 1);
}

#[test]
fn nesting_costs_more_than_sequence() {
    // Two ifs in sequence: 1 + 1.
    let flat = one("void f(int a, int b) { if (a) { a++; } if (b) { b++; } }", "f");
    assert_eq!(flat.shape.cognitive, 2);
    assert_eq!(flat.shape.max_nesting, 1);
    assert_eq!(flat.parameters, 2);

    // The same two ifs nested: 1 + (1 + 1).
    let nested = one("void g(int a, int b) { if (a) { if (b) { a++; } } }", "g");
    assert_eq!(nested.shape.cognitive, 3);
    assert_eq!(nested.shape.max_nesting, 2);

    // Both have the same number of decisions. That is the whole point of
    // reporting cognitive complexity beside the cyclomatic one.
    assert_eq!(flat.graph.decision_points, nested.graph.decision_points);
}

#[test]
fn an_else_if_ladder_is_not_charged_as_nesting() {
    // if / else if / else if / else. Under the specification: +1 for the `if`,
    // +1 for each `else if`, +1 for the final `else`, and no nesting penalty on
    // any of them.
    let f = one(
        "int f(int a) { if (a == 1) { return 1; } \
         else if (a == 2) { return 2; } \
         else if (a == 3) { return 3; } \
         else { return 0; } }",
        "f",
    );
    assert_eq!(f.shape.cognitive, 4);
}

#[test]
fn a_run_of_like_logical_operators_costs_one() {
    let single = one("int f(int a, int b, int c) { if (a && b && c) { return 1; } return 0; }", "f");
    assert_eq!(
        single.shape.cognitive, 2,
        "+1 for the if, +1 for the single && run"
    );

    let mixed = one("int g(int a, int b, int c) { if (a && b || c) { return 1; } return 0; }", "g");
    assert_eq!(
        mixed.shape.cognitive, 3,
        "+1 for the if, +1 for the && run, +1 for the || run"
    );
}

#[test]
fn loops_nest_and_are_counted_as_loops() {
    let f = one(
        "void f(int n) { for (int i = 0; i < n; i++) { while (n) { n--; } } }",
        "f",
    );
    assert_eq!(f.shape.max_loop_depth, 2);
    assert_eq!(f.shape.cognitive, 3, "for at 0, while at nesting 1");
    assert_eq!(f.graph.loops, 2, "two back-edge destinations");
    assert!(f.graph.back_edges >= 2);
}

#[test]
fn a_goto_is_charged_but_not_nested() {
    let f = one(
        "void f(int a) { if (a) { goto done; } a++; done: return; }",
        "f",
    );
    assert_eq!(f.shape.cognitive, 2, "+1 for the if, +1 for the goto");
    assert_eq!(*f.shape.tag_counts.get("goto_stmt").unwrap_or(&0), 1);
    assert_eq!(*f.shape.tag_counts.get("label_stmt").unwrap_or(&0), 1);
}

#[test]
fn code_after_a_return_is_reported_as_unreachable() {
    let f = one("int f(void) { return 1; return 2; }", "f");
    assert_eq!(f.unreachable_statements, 1, "the second return");
    // The general CFG never contains it, so the graph's own count is zero --
    // which is exactly why `unreachable_statements` is a separate figure.
    assert_eq!(f.graph.unreachable_nodes, 0);
    // And it does not inflate the cyclomatic number either way.
    assert_eq!(f.graph.cyclomatic, 1);
}

#[test]
fn code_after_a_goto_is_reported_as_unreachable() {
    let f = one("void f(void) { goto skip; orphan(); skip: return; }", "f");
    assert_eq!(f.unreachable_statements, 1, "the orphan() call");
}

#[test]
fn live_code_is_not_reported_as_unreachable() {
    let f = one("void f(int a) { if (a) { return; } a++; }", "f");
    assert_eq!(f.unreachable_statements, 0);
}

#[test]
fn unreachable_detection_is_a_lower_bound_after_an_always_true_loop() {
    // Documented limitation: no constant folding, so the loop header still
    // carries a false arm to the statement after it and nothing reports it.
    // Pinned as a test so the day it improves, this fails and says so.
    let f = one("void f(void) { for (;;) { } orphan(); }", "f");
    assert_eq!(
        f.unreachable_statements, 0,
        "constant folding would make this 1; see FunctionMetrics::unreachable_statements"
    );
}

#[test]
fn halstead_counts_operators_by_kind_and_operands_by_text() {
    // int f(int a) { return a + a + 1; }
    //
    // Operators, by kind, ignoring the closing half of each pair:
    //   int (x2 -> 1 distinct), f's `(`, `{`, `+`, return, `;`
    //   -> kinds: KwInt, LParen, LBrace, Plus, KwReturn, Semi  = 6 distinct
    // Operands, by text: `f`, `a`, `1` = 3 distinct; occurrences f,a,a,a,1 = 5.
    let f = one("int f(int a) { return a + a + 1; }", "f");
    assert_eq!(f.halstead.distinct_operators, 6, "{:?}", f.halstead);
    assert_eq!(f.halstead.distinct_operands, 3, "{:?}", f.halstead);
    assert_eq!(f.halstead.total_operands, 5, "{:?}", f.halstead);
    // N1: int, (, int, ), {, return, +, +, ;, } -> closing ) and } do not count.
    assert_eq!(f.halstead.total_operators, 8, "{:?}", f.halstead);

    assert_eq!(f.halstead.vocabulary(), 9);
    assert_eq!(f.halstead.length(), 13);
    // V = 13 * log2(9); D = (6/2) * (5/3).
    let volume = 13.0 * 9.0f64.log2();
    assert!((f.halstead.volume() - volume).abs() < 1e-9);
    assert!((f.halstead.difficulty() - 3.0 * (5.0 / 3.0)).abs() < 1e-9);
}

#[test]
fn calls_are_counted_and_direct_callees_named() {
    let f = one("void f(void) { g(); h(g()); p->fn(); }", "f");
    assert_eq!(f.shape.calls, 4, "g, h, the inner g, and p->fn");
    assert_eq!(
        f.shape.callees,
        vec!["g".to_string(), "h".to_string()],
        "an indirect call through a member has no name to record"
    );
}

#[test]
fn line_counts_split_code_blank_and_comment() {
    let text = "int f(void)\n{\n\n    // a comment\n    return 1;\n}\n";
    let report = analyze(text).into_parts().0;
    assert_eq!(report.lines.code_lines, 4, "the four lines carrying tokens");
    assert_eq!(report.lines.blank_lines, 2, "line 3 and the trailing empty");
    assert_eq!(report.lines.other_lines, 1, "the comment line");

    let f = report.functions.into_iter().next().expect("one function");
    assert_eq!(f.size.first_line, 1);
    assert_eq!(f.size.last_line, 6);
    assert_eq!(f.size.lines, 6);
}

#[test]
fn a_declaration_without_a_body_is_not_a_function() {
    let report = analyze("int f(int a);\nint g(void) { return 0; }").into_parts().0;
    let names: Vec<&str> = report.functions.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["g"]);
}

#[test]
fn analysis_is_total_on_input_that_is_not_c() {
    // REQ-SYN-2: no input panics, and a file that recovers nothing still
    // reports a file-level measurement rather than an error.
    for text in [
        "",
        "\0\0\0",
        "int f(void) { if (",
        "}}}}}}",
        "int f(void) { return 1; } garbage garbage",
        "#define X(",
    ] {
        let parsed = analyze(text);
        let report = parsed.value();
        assert_eq!(report.bytes, text.len() as u32, "input {text:?}");
    }
}

#[test]
fn the_measurement_is_deterministic() {
    let text = "int f(int a, int b) { if (a && b) { while (a) { a--; } } return a; }";
    let first = analyze(text).into_parts().0;
    let second = analyze(text).into_parts().0;
    assert_eq!(first, second);
}

#[test]
fn a_recovered_function_still_reports_its_siblings() {
    // REQ-ROB-2: one broken definition must not void the file.
    let report = analyze("int broken(void) { if ( } int fine(void) { return 1; }")
        .into_parts()
        .0;
    assert!(
        report.functions.iter().any(|f| f.name == "fine"),
        "recovered: {:?}",
        report.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
}

#[test]
fn a_constructs_header_is_not_inside_its_body() {
    // The specification nests the *body*, not the header. A `?:` in a
    // controlling expression is evaluated where the construct sits, so it is
    // charged 1 and not 1 + 1.
    //
    // Every case here scored one higher before the header/body split, and no
    // other test in this file distinguished the two, so this is what keeps the
    // implementation and the module docs agreeing.
    let cases = [
        // while: +1 for the while at 0, +1 for the ternary at 0.
        ("void f(int a, int b, int c) { while (a ? b : c) { c++; } }", 2),
        // for, all three clauses: same rule, and the clause tags must not read
        // as body statements.
        ("void g(int a, int b, int c) { for (a = 0; a < (b ? c : 1); a++) { c++; } }", 2),
        // switch selector.
        ("void h(int a, int b, int c) { switch (a ? b : c) { case 1: break; } }", 2),
        // do-while, whose condition follows its body rather than preceding it.
        ("void i(int a, int b, int c) { do { c++; } while (a ? b : c); }", 2),
    ];
    for (text, expected) in cases {
        let name = text.split_whitespace().nth(1).unwrap();
        let name = &name[..name.find('(').unwrap()];
        let f = one(text, name);
        assert_eq!(
            f.shape.cognitive, expected,
            "header should not nest, in: {text}"
        );
    }

    // And the contrast: the same ternary in the *body* does nest.
    let nested = one("void f(int a, int b, int c) { while (a) { c = b ? c : 1; } }", "f");
    assert_eq!(
        nested.shape.cognitive, 3,
        "+1 for the while at 0, +1+1 for the ternary at nesting 1"
    );
}

#[test]
fn a_ternary_nests_its_arms_but_not_its_condition() {
    // A ternary whose condition holds another ternary: outer +1 at 0, inner +1
    // at 0 as well, because the condition is not an arm.
    let in_condition = one("int f(int a, int b) { return (a ? b : 0) ? 1 : 2; }", "f");
    assert_eq!(in_condition.shape.cognitive, 2);

    // The same ternary in an arm is one level deeper: +1 then +1+1.
    let in_arm = one("int g(int a, int b) { return a ? (b ? 1 : 2) : 3; }", "g");
    assert_eq!(in_arm.shape.cognitive, 3);
}

// --- the in-repo corpus ------------------------------------------------------

/// Every `.c` file under `root`, sorted, so a run is reproducible.
fn c_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("c") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

#[test]
fn the_in_repo_corpus_measures_without_panicking_and_holds_its_invariants() {
    // Asserted rather than skipped: both trees are committed to this
    // repository, so an empty list is a broken checkout, and a corpus gate that
    // skips silently is indistinguishable from one that passes.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for relative in ["tests/decompiler_fixtures/src", "tests/decbench_corpus/src"] {
        files.extend(c_files(&root.join(relative)));
    }
    assert!(
        files.len() > 100,
        "expected the in-repo C corpus, found {} files under {}",
        files.len(),
        root.display()
    );

    let mut functions = 0u64;
    let mut with_loops = 0u64;
    let mut with_switch = 0u64;
    let mut with_goto = 0u64;
    let mut unreachable = 0u64;
    let mut max_cyclomatic = 0u32;
    let mut max_cognitive = 0u32;

    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let report = analyze(&text).into_parts().0;
        assert!(
            report.lines.code_lines + report.lines.blank_lines + report.lines.other_lines
                == report.lines.lines,
            "line categories must partition the file, in {}",
            path.display()
        );

        for f in &report.functions {
            functions += 1;
            let where_ = || format!("{}::{}", path.display(), f.name);

            // A function with a body always has at least one path through it.
            assert!(f.graph.cyclomatic >= 1, "cyclomatic floor in {}", where_());
            // Extra sinks only ever lower `E - N + 2` below `decisions + 1`.
            assert!(
                f.graph.cyclomatic <= f.graph.decision_points + 1,
                "cyclomatic {} exceeds decisions+1 {} in {}",
                f.graph.cyclomatic,
                f.graph.decision_points + 1,
                where_()
            );
            assert!(
                f.size.code_lines <= f.size.lines,
                "code lines exceed physical lines in {}",
                where_()
            );
            assert_eq!(
                f.halstead.length(),
                f.halstead.total_operators + f.halstead.total_operands,
                "Halstead length is its two totals in {}",
                where_()
            );
            assert!(
                f.halstead.distinct_operators <= f.halstead.total_operators,
                "distinct operators exceed occurrences in {}",
                where_()
            );
            assert!(
                f.graph.reachable_nodes <= f.graph.nodes,
                "reachable exceeds total in {}",
                where_()
            );
            assert!(
                !f.shape.truncated,
                "the visit budget stopped a real corpus function in {}",
                where_()
            );

            if f.graph.loops > 0 {
                with_loops += 1;
            }
            if f.shape.tag_counts.contains_key("switch_stmt") {
                with_switch += 1;
            }
            if f.shape.tag_counts.contains_key("goto_stmt") {
                with_goto += 1;
            }
            unreachable += u64::from(f.unreachable_statements);
            max_cyclomatic = max_cyclomatic.max(f.graph.cyclomatic);
            max_cognitive = max_cognitive.max(f.shape.cognitive);
        }
    }

    println!(
        "in-repo corpus: {} files, {functions} functions, {with_loops} with loops, \
         {with_switch} with a switch, {with_goto} with a goto, {unreachable} unreachable \
         statements, max cyclomatic {max_cyclomatic}, max cognitive {max_cognitive}",
        files.len()
    );

    // A corpus that exercised none of these would make every assertion above
    // vacuous, which is the failure mode a census gate exists to catch.
    assert!(functions > 500, "only {functions} functions measured");
    assert!(with_loops > 0 && with_switch > 0 && with_goto > 0);
    assert!(max_cyclomatic > 5, "no branchy function in the corpus?");
    assert!(max_cognitive > 5, "no nested function in the corpus?");
}
