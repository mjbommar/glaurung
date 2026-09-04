/* Decompiler-dialect fixture -- Ghidra.
 *
 * PROVENANCE: captured output, not a reconstruction. Produced on this machine
 * by Ghidra 12.1.3 PUBLIC (headless) over binaries that live in this
 * repository, with:
 *
 *   /opt/ghidra/support/analyzeHeadless <projdir> <projname> \
 *     -import <binary> -scriptPath <dir> \
 *     -postScript DumpDecompiledC.java <out.c> -deleteProject
 *
 * where DumpDecompiledC.java walks getFunctionManager().getFunctions(true) and
 * prints DecompInterface.decompileFunction(f, 60, monitor).getDecompiledFunction().getC()
 * with a "// Function: <name> @ <entry>" marker. Each case below is one
 * function's text copied verbatim from that dump; nothing was edited.
 *
 * Read with docs/design/source-front-ends/decompiler-dialects.md.
 */

/* case: parse_record
 * provenance: captured
 * source: samples/binaries/platforms/linux/amd64/synthetic/vulnparse-c-gcc-O0
 * expect: parse_record
 * note: Ghidra's ordinary house style: undefined/uchar/byte pseudo-types,
 * note: in_FS_OFFSET stack-guard reads, /* WARNING: ... */ comments.
 * note: All of it parses; none of it is standard C typedef'd anywhere.
 */
void parse_record(uchar *input,size_t total_len)

{
  byte bVar1;
  long lVar2;
  long in_FS_OFFSET;
  size_t total_len_local;
  uchar *input_local;
  uchar declared_len;
  char buf [64];
  
  lVar2 = *(long *)(in_FS_OFFSET + 0x28);
  if (total_len != 0) {
    bVar1 = *input;
    if (total_len - 1 < (ulong)bVar1) {
      fwrite("short input\n",1,0xc,stderr);
    }
    else {
      memcpy(buf,input + 1,(ulong)bVar1);
      buf[(int)(uint)bVar1] = '\0';
      printf("record: %s\n",buf);
    }
  }
  if (lVar2 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}


/* case: _start
 * provenance: captured
 * source: samples/binaries/platforms/linux/amd64/synthetic/vulnparse-c-gcc-O0
 * expect: -
 * gap: calling-convention keyword in the declarator (processEntry)
 * note: Ghidra prints the calling convention it assigned between the return
 * note: type and the name. 'processEntry' is Ghidra's own convention name, not
 * note: an MSVC keyword, so a fix that whitelists __cdecl/__stdcall/__fastcall/
 * note: __thiscall does not cover it. Every ELF executable has one of these.
 */
void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  __libc_start_main(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}


/* case: switchD_001011b2::caseD_0
 * provenance: captured
 * source: samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-stripped
 * expect: -
 * gap: '::' in the function name of a jump-table stub
 * note: Ghidra names recovered switch stubs switchD_<addr>::caseD_<n> and
 * note: switchD_<addr>::default, so C output for any jump table carries a C++
 * note: qualified name. Joern's C frontend does not parse this either.
 */
int switchD_001011b2::caseD_0(undefined8 param_1,undefined8 param_2,int param_3)

{
  int in_EAX;
  
  return in_EAX + param_3;
}


/* case: FUN_00108540
 * provenance: captured
 * source: tests/decompiler_fixtures/build/219_rust_iterator_chains-rustc-O2strip.so
 * expect: -
 * gap: aggregate/array return type: undefined1 [16] name(void)
 * note: This is quirk 1 of DecBench's sanitize_decompiled_c: Joern parses
 * note: nothing for such a function, so DecBench rewrites the signature to
 * note: 'undefined1 name(void)' before Joern sees it. We do not sanitize.
 */
undefined1  [16] FUN_00108540(void)

{
  undefined1 auVar1 [16];
  
  auVar1._8_8_ = 0xfdbc168100b1ef64;
  auVar1._0_8_ = 0xc1a2c89ccd1e7bc1;
  return auVar1;
}


/* case: DllCanUnloadNow
 * provenance: captured
 * source: samples/binaries/platforms/windows/vendor/realworld/win11-SyncInfrastructureps.dll
 * expect: DllCanUnloadNow
 * note: __stdcall in the declarator. This was a gap until the lexer/parser
 * note: calling-convention work landed; it is kept as a regression case.
 */
HRESULT __stdcall DllCanUnloadNow(void)

{
  HRESULT HVar1;
  
                    /* 0x1e50  1  DllCanUnloadNow */
                    /* WARNING: Could not recover jumptable at 0x000180001e57. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  HVar1 = NdrDllCanUnloadNow(&DAT_18000a620);
  return HVar1;
}


/* case: Base::op
 * provenance: captured
 * source: tests/decompiler_fixtures/build/10_cpp_runtime_shapes-gcc-O2strip.so
 * expect: -
 * gap: __thiscall plus a '::' qualified name
 * note: Ghidra emits __thiscall for C++ methods even in its C output. The two
 * note: quirks arrive together, so fixing only the keyword does not recover it.
 */
/* Base::op(int) */

int __thiscall Base::op(Base *this,int param_1)

{
  return param_1 + 1000;
}
