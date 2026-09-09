# WP3 call-target layout expression origins

Commit `71123306` closes two call-layout proof boundaries that still inspected
raw target expressions. Provenance on a direct named/address target could hide
its recovered callee layout, while provenance on a relocation-proven function
table could hide the complete entry set used to compute its ABI may-use set.

Both behavioral contracts were observed red before the repair. The attributed
ARM hard-float target degraded a source-ordered `(r0, s0, r1)` call to two
arguments and left the VFP setup behind. The attributed table target recovered
zero of its two proven arguments. Both readers now inspect `Expr::semantic()`;
the attributed target itself remains unchanged.

Exactly five Rust tests passed after the repair:

```text
recovered_callee_layout_interleaves_arm_core_and_vfp_arguments    pass
a_proven_table_call_reads_the_enclosing_reaching_definitions      pass
a_table_entry_with_no_recovered_layout_leaves_the_call_alone      pass
disagreeing_table_entry_layouts_are_not_unioned                   pass
origin_wrappers_do_not_hide_register_names_from_call_recovery     pass
```

Each invocation filtered out 4,726 unrelated tests. An exact detached release
build then passed the compiled ARM mixed hard-float round trip and the exact
GCC-O0 `95_function_pointer_table::dispatch_operation` fixture. The adjacent
GCC-O2 table cell reports a committed-baseline regression at both `71123306`
and its exact parent `51b07fa4`, with identical zero-argument table-call output;
that separate pre-existing WP3/WP8 call-contract defect is not attributed to
this change. Follow-up `a4d8598a` identifies and closes its statement-owner
half; see `wp3-table-call-statement-origins.md`.

The periodic O2 symbol-bearing PIE Hello sample passed on x86-64, AArch64, and
ARMv7 (**3/3**). No broad Rust, Python, fixture, DecBench, or Joern suite ran.
This closes these two target readers, not universal production attribution or
WP3 as a whole.
