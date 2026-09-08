# WP3/WP6 hosted Hello contract

Two focused production fixes restore the canonical Hello World output across
the four periodic canary cells.

- Commit `76eb1329` makes call-argument pointer-type comparison transparent to
  `Expr::Origin`. An attributed string literal passed to `const char *` now
  uses C's ordinary qualification conversion instead of rendering a redundant
  `(const char *)` cast.
- Commit `fea34010` extends the existing authoritative hosted-`main` rule from
  the two-argument form to the other standard recovered arity. A zero-argument
  body now renders `int main(void)` even when machine-width inference proposes
  an unsigned word return. Explicit source prototypes still win, void output
  is refused, and nonstandard arities retain inference.

The exact new Rust tests and their four- and six-test owning modules pass. A
fresh debug extension passes `tools/build_guard.py`. The four exact canonical
Python cells—amd64 and AArch64, Clang O0 and O2, symbol-bearing PIE—now all
pass and render:

```c
int main(void) {
    extern int puts(const char *);
    puts("Hello, World!");
    return 0;
}
```

The census records 5,144 declared Rust tests and zero outside every gate; all
six census checks pass after each source commit. No broad Rust suite, Python
suite, fixture matrix, DecBench, or Joern lane ran.
