# WP3 zero-setup call-target expression origins

Commit `1366b33a` makes the convention-generic zero-setup forwarding proof
transparent to expression-origin carriers on a direct callee. An attributed
named target no longer makes a first value-producing call appear indirect and
drop an otherwise proven untouched leading parameter.

The proof remains fail-closed. It still requires a named direct target, no
earlier call, no reconstructed arguments, a used result, a supported calling
convention, an entry-reachable call, and an untouched source-parameter slot.
Only the target's semantic expression is inspected through its provenance
wrapper.

The SysV and AAPCS contracts were each observed red before the production
repair: both recovered an empty argument list instead of forwarding `rdi` or
`r0`. After repair, the two exact tests and the complete forwarding slice pass:

```text
first_value_producing_call_forwards_an_untouched_leading_parameter: 1 passed
an_aapcs_zero_setup_call_forwards_the_incoming_first_parameter:     1 passed
forwards_:                                                          6 passed
```

An exact detached release build of `1366b33a` was fresh. The directly relevant
`call_result_drives_branch` function passes in all four selected O2 cells:

```text
11_call_shapes:clang:O2:call_result_drives_branch    pass
11_call_shapes:gcc:O2:call_result_drives_branch      pass
11_call_shapes:aarch64:O2:call_result_drives_branch  pass
11_call_shapes:armv7:O2:call_result_drives_branch    pass
```

The real fixture run took 4.3 seconds. No broad Rust, Python, fixture, DecBench,
or Joern suite ran. The periodic six-cell GCC symbols/PIE Hello checkpoint was
not repeated because it had just passed at exact commit `bf8718e9` across O0
and O2 on x86-64, AArch64, and ARMv7.

This closes one bounded call-argument consumer, not WP3. Authoritative SSA
identity, explicit invalidation, and the remaining expression-origin consumer
audit stay open.
