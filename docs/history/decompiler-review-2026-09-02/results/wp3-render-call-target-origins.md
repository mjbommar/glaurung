# WP3 rendered call-target origins

Commit `44338752` closes three adjacent output-facing expression-origin holes
in the shared AST identifier and rendering boundary.

- Call-target name lookup now inspects the semantic expression, so attribution
  no longer removes WinAPI prototype hints from plain or C-style output.
- Statement-call identifier collection recognizes an attributed named target
  as a callee rather than treating it as an indirect value expression.
- The same collection retains `__stack_chk_fail` evidence through attribution,
  preventing scored C from incorrectly adding `no_stack_protector` to a
  function whose original binary demonstrably had a canary.

Both strengthened contracts were observed red before the repair: the
attributed `ReadFile` target lost its prototype hint, and the attributed
`__stack_chk_fail@plt` target left `calls_stack_check` false. The repair changes
only semantic classification; the exact origin carriers remain attached.

Focused validation:

```text
winapi_calls_render_prototype_hints_without_changing_call_syntax: 1 passed
attributed_stack_check_target_keeps_protector_evidence: 1 passed
python/tests/test_proto_hints.py::test_proto_hint_appears_for_libc_call: 1 passed
test_a_recovered_frame_array_does_not_invite_a_stack_protector[x86_64]: 1 passed
```

The Python checks used a detached clean release build of exact commit
`44338752`; the native build guard reported `fresh`. No broad suite ran.

The periodic Hello checkpoint covered exactly six GCC symbols/PIE cells:

| Architecture | O0 | O2 |
|---|---:|---:|
| x86-64 | pass | pass |
| AArch64 | pass | pass |
| ARMv7 | pass | pass |

This closes one bounded renderer/identifier-consumer family, not WP3. The
remaining enabled expression consumers and universal production attribution
stay open.
