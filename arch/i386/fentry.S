/* argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9 */
/* return value: %rax */
/* callee saved: %rbx, %rbp, %rsp, %r12-r15 */
/* stack frame (with -pg -mfentry): parent addr = 8(%rsp), child addr = (%rsp) */
/*
 * For example:

   Parent(caller): main()
   Child(callee): hello()

   Dump of assembler code for function main:
                   0x00000000004006bc <+0>:	callq  0x400550 <__fentry__@plt>
                   0x00000000004006c1 <+5>:	push   %rbp
                   0x00000000004006c2 <+6>:	mov    %rsp,%rbp
                   0x00000000004006c5 <+9>:	mov    $0x0,%eax
                   0x00000000004006ca <+14>:	callq  0x4006a6 <hello>
    parent addr => 0x00000000004006cf <+19>:	nop
                   0x00000000004006d0 <+20>:	pop    %rbp
                   0x00000000004006d1 <+21>:	retq

   Dump of assembler code for function hello:
                   0x00000000004006a6 <+0>:	callq  0x400550 <__fentry__@plt>
     child addr => 0x00000000004006ab <+5>:	push   %rbp
                   0x00000000004006ac <+6>:	mov    %rsp,%rbp
 */

#include "utils/asm.h"

GLOBAL(__fentry__)
	sub $32, %esp
	movl %edx, 20(%esp)
	movl %ecx, 16(%esp)
	movl %eax, 12(%esp)

	/* parent location */
	leal 4(%ebp), %eax
	movl %eax, 0(%esp)
	/* child addr */
	movl 32(%esp), %eax
	movl %eax, 4(%esp)

	/* mcount_args */
	leal 16(%esp), %eax
	movl %eax, 8(%esp)

	call mcount_entry
	cmpl $0, %eax
	jne 1f

	/* hijack return address */
	call __x86.get_pc_thunk.ax
	addl $_GLOBAL_OFFSET_TABLE_, %eax
	addl $fentry_return@GOTOFF, %eax
	movl %eax, 36(%esp)
1:
	movl 12(%esp), %eax
	movl 16(%esp), %ecx
	movl 20(%esp), %edx
	add $32, %esp
	ret
END(__fentry__)


ENTRY(fentry_return)
	sub  $32, %esp
	movl %edx, 12(%esp)
	movl %ecx, 8(%esp)
	movl %eax, 4(%esp)

	leal 8(%esp), %eax
	movl %eax, 0(%esp)

	call mcount_exit
	movl %eax, 28(%esp)

	movl 4(%esp), %eax
	movl 8(%esp), %ecx
	movl 12(%esp), %edx

	add  $28, %esp
	ret
END(fentry_return)
