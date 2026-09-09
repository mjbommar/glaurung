# WP3 exception expression reconstruction

Commit `34d25589` closes the exception-body boundary in `expr_reconstruct`.

Expression reconstruction removes a lifter temporary only when its sole use is
in the immediately following statement. The global conservative census already
visited exception bodies, but the transformation did not recurse into try/catch
bodies, treated a throw value as having no direct reads, and could not substitute
into a throw. Compiler temporaries therefore remained visible in exception
output even when all ordinary safety conditions held.

The pass now reconstructs independently inside each try and catch body, counts
throw-value reads, and substitutes into the throw expression. It still refuses
to move a definition from outside into a nested exception body: only two
adjacent statements in the same body are eligible. Definition, use-expression,
definition-statement, and throw-statement owners transfer under the existing
composition contract.

## Focused evidence

The new contract was observed red first: the temporary assignment survived in
the try body. After repair it becomes one throw of the direct constant with the
expected value and statement origin unions.

```text
cargo test --features python-ext --lib \
  ir::expr_reconstruct::tests::temporary_immediately_consumed_by_throw_is_reconstructed \
  -- --exact --quiet
1 passed; 4,738 filtered out

cargo test --features python-ext --lib ir::expr_reconstruct::tests:: --quiet
13 passed; 4,726 filtered out
```

An exact detached release build of `34d25589` passed the build guard with native
SHA-256 `2d6660e5b309636f93ba4f11a6a91d2c37aaf53e869a53e392bc3fa6410601a6`.
The adjacent general reconstruction control remained green:

```text
python tools/dectest.py \
  '01_conditional_polarity:*:*:classify' --jobs 2 --full --show
4 passed across Clang/GCC O0/O2; no regressions in scope
```

No checked-in real fixture currently exercises the structured exception AST,
so that path is pinned directly by the Rust contract. No broad Rust, Python,
fixture, architecture, DecBench, or Joern suite ran.
