# IOSTAT post-call checks (Bug U resolution)

The Bug L audit emitted a [low] `missing_error_path` finding:

> libgfortran I/O sequences wrap st_write/transfer/st_write_done;
> if any sets the dtparm common error flags, gfortran-emitted code
> branches to error reporting. With 5 functions missing and no
> error handling visible in the 2-function recovery, the rewrite
> has likely silenced these post-call status checks. Benign at
> runtime for a hello-world but a faithfulness gap.
>
> → _Restore the post-call status checks around
>    `_gfortran_st_write_done`, even if they appear dead at -O2._

## Why we did not "restore" the checks

The audit was wrong on this one. We confirmed by `objdump -d`
that **the binary has no IOSTAT branches** after any of the
`_gfortran_st_write_done` calls:

```
1254:    call   1060 <_gfortran_st_write_done@plt>
1259:    call   1080 <_gfortran_iargc@plt>
1322:    call   1060 <_gfortran_st_write_done@plt>
1327:    mov    %rbp,%rdi
1373:    call   1060 <_gfortran_st_write_done@plt>
1378:    mov    %rbp,%rdi
```

Every site is followed immediately by the next normal-flow
instruction. There is no `test`/`cmp`/`jcc` on any byte of the
descriptor between the calls.

## Why the binary has no checks

The Fortran source `hello.f90` uses bare `print *` statements with
no `IOSTAT=` clause. Without `IOSTAT=`, gfortran has no obligation
to emit post-call branches — it lets libgfortran's default
behaviour (abort on hard errors) handle the rare failure case.
At `-O2`, even speculative checks the front-end might have
inserted are dead-code-eliminated.

The audit's recommendation — "restore the checks even if they
appear dead at -O2" — would *decrease* faithfulness: the
recovered C would have branches the original binary doesn't
have, and `glaurung diff` against a re-compile of the recovered
source would surface them as a regression.

## Conclusion

The recovered C correctly omits IOSTAT post-call checks because
the binary correctly omits them. **Bug U closed as audit
mis-finding, not a code change.**

If a future Fortran sample uses `IOSTAT=` and the binary DOES
emit branches, the rewriter must reproduce them — that's a
different test case (filed for the canonical-corpus expansion
under #197 / #213's spiritual successor).
