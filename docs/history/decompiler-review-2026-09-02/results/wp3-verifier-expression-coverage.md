# WP3 verifier expression coverage

Commit `ffb5d009` completes the dangerous frame-address verifier's recursive
expression coverage. A frame register used as an address is unsafe in emitted C
because the renderer declares it as an uninitialised local. The verifier already
recognized direct statement-call arguments and dereferences, but nested value
calls and several later AST forms could hide the same address use.

The scanner now handles every current expression variant explicitly. It follows
origin carriers, numeric conversions, calls, selects, PDB field addresses,
function-table indices, and wide arithmetic. Address-use roots remain narrow:
call targets and arguments, indirect-goto targets, dereference addresses, LEA
and PDB field addresses, store addresses, and function-table indices. A plain
frame-register value remains outside this high-confidence crash diagnostic.

## Focused evidence

The attributed nested-call contract was observed red first. At the committed
implementation:

```text
cargo test --features python-ext --lib \
  nested_call_argument_cannot_hide_an_attributed_frame_pointer_address
1 passed; 4,747 filtered out

cargo test --features python-ext --lib ir::verify_defs::tests::
49 passed; 4,699 filtered out
```

An exact release build of `ffb5d009` produced native SHA-256
`8ef84141afb2125bac9c3c0c04e2183581a857deae4a4d28d99c3facd442e8dc`.
The exact GCC-O2 exception specimen remains verifier-clean and renders
byte-identically to the immediately preceding form. The one real
pipeline-profile output-transparency test also passes.

This is a verifier/origin-consumer closure, not a rendered-code transformation.
The periodic six-cell Hello checkpoint passed on the preceding exact release
increment and was not repeated. No broad Rust, Python, fixture, architecture,
DecBench, or Joern suite ran.
