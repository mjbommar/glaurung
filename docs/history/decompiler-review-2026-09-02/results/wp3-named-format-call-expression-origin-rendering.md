# WP3 named format-call expression-origin rendering

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `5e49845e` makes the named-call declaration and format-contract path
transparent to expression-origin carriers. A provenance wrapper around a
direct named target no longer turns it into an indirect call, and a wrapper
around a literal `printf`-family format no longer disables variadic argument
typing.

The repair spans the coherent consumer boundary: call-site prototype recovery,
named-callee observation, rendered direct-call selection, symbolic-constant
callee selection, and literal format parsing all inspect the semantic target;
the format parser likewise inspects the semantic format expression. An actual
indirect target still declines every named-callee rule.

## Focused TDD

The existing `%d` contract was strengthened with independent origins on the
named `printf` target and literal format. The first RED result degraded the
whole call:

```text
((void (*)(long, long))(0x2000))(
    (long)("value: %d\n"),
    (unsigned long)((unsigned int)(var0)))
```

After the renderer recognized the named target, the test remained red because
the named-call observation pass still missed the wrapper and therefore kept
the variadic argument as the recovered fixed `long`. Making that upstream
observation semantic restored the full contract:

```text
printf("value: %d\n", var0);
```

Focused results:

```text
cargo test --features python-ext --lib \
  ir::ast::tests::decbench_uses_literal_printf_format_to_type_variadic_int \
  -- --exact
1 passed; 0 failed; 4,674 filtered out

cargo test --features python-ext --lib \
  ir::ast::tests::declared_pointer_call_keeps_parameter_types_when_result_needs_conversion \
  -- --exact
1 passed; 0 failed; 4,674 filtered out

cargo test --features python-ext --lib ir::ast::named_calls::tests -- --nocapture
3 passed; 0 failed; 4,672 filtered out
```

## Release evidence and limitation

The required release extension rebuilt successfully. The single real stripped
format-environment test was then selected:

```text
uv run --no-sync pytest \
  python/tests/test_format_environment.py::test_real_stripped_local_vfprintf_sink_types_literal_format_operands -q
```

It is red on the concurrent shared snapshot at its first textual assertion:
the decompiler correctly recovers the parameter as `char *arg0`, while the
test searches for the older whitespace spelling `char * arg0`. This increment
does not own declaration whitespace. The run is recorded as a shared-snapshot
limitation, not as green real-binary evidence, and the test was not edited or
hidden.

## Scope

This closes one bounded WP3 call-expression origin consumer. It does not infer
new formats, relax the parser's fail-closed unsupported-format rules, or
complete universal expression attribution.
