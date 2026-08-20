/* Anti-disassembly: jumps that land inside an instruction a linear sweep has
 * already consumed.
 *
 * Every trick here has the same shape. A junk opcode byte is placed where the
 * sweep will read it, and a short jump steps over it. The junk byte is chosen
 * so that the sweep's decoding of it swallows part of the *next real
 * instruction*, which puts the sweep permanently out of phase with the bytes
 * the CPU actually executes. Recursive descent, which follows the jump, sees
 * the real instruction stream.
 *
 * The two disassemblies therefore disagree, and they disagree about executable
 * bytes rather than about metadata. That is the point: `strip`, `sstrip` and
 * `objcopy --rename-section` all leave the code identical and only lie about
 * what surrounds it, so they cannot tell us anything about this failure mode.
 *
 * There is deliberately no `.cfi_startproc` here. Hand-written assembly in real
 * samples does not carry unwind tables, and the FDE would hand a reader the
 * function's start and length for free, which is exactly the information the
 * shape is supposed to withhold.
 *
 * Position independent: register arithmetic and short relative jumps only, so
 * this links into the ordinary PIE build with no textrels.
 *
 * `glaurung_overlap_probe(x)` returns `x * 7 + 3`, and the corpus driver calls
 * it and checks the answer. A variant that does not execute is not evidence
 * about anything, and self-modifying-looking code that quietly computes the
 * wrong thing would be worse than useless.
 */

	.text
	.globl	glaurung_overlap_probe
	.type	glaurung_overlap_probe, @function
glaurung_overlap_probe:
	movl	%edi, %eax

	/* Trick 1 -- lone 0xE8.
	 * The sweep reads `call rel32` and consumes four more bytes: the whole
	 * of the `imul` below (6b c0 07) plus the first byte of trick 2. */
	xorl	%ecx, %ecx
	jz	1f			/* 74 01 -- always taken */
	.byte	0xe8
1:
	imull	$7, %eax, %eax		/* 6b c0 07 */

	/* Trick 2 -- lone 0xB8.
	 * `mov eax, imm32` eats the three bytes of the `add` and one more,
	 * so the sweep never sees the add at all. */
	testl	%ecx, %ecx
	je	2f			/* 74 01 */
	.byte	0xb8
2:
	addl	$3, %eax		/* 83 c0 03 */

	/* Trick 3 -- lone 0x05.
	 * `add eax, imm32` swallows four bytes of the epilogue. */
	jmp	3f			/* eb 01 */
	.byte	0x05
3:
	movl	%eax, %edx		/* 89 c2 */
	movl	%edx, %eax		/* 89 d0 */
	ret

	.size	glaurung_overlap_probe, .-glaurung_overlap_probe

/* A second hostile function, so that the measurement is not one accident.
 *
 * This one is a true overlap rather than a skipped junk byte: the four bytes
 * after the 0x0F are a real two-byte opcode plus operands under one decoding
 * and an independent instruction sequence under the other, and control flow
 * reaches the second decoding.
 *
 * `glaurung_overlap_maze(x)` returns `x + 11`.
 */
	.globl	glaurung_overlap_maze
	.type	glaurung_overlap_maze, @function
glaurung_overlap_maze:
	movl	%edi, %eax
	xorl	%ecx, %ecx

	/* `0f 84` would be `jz rel32`; the sweep takes 0x0f as the start of a
	 * two-byte opcode and reads the `add` that follows as its operand. */
	jz	4f			/* 74 01 */
	.byte	0x0f
4:
	addl	$11, %eax		/* 83 c0 0b */

	/* Jump backwards over our own tail and forwards again, so that a reader
	 * that stops at the first `ret` stops in the middle of the function. */
	jmp	6f
5:
	ret
6:
	testl	%ecx, %ecx
	jz	5b

	.size	glaurung_overlap_maze, .-glaurung_overlap_maze

	.section	.note.GNU-stack,"",@progbits
