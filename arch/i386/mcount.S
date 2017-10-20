/* in i386, generally used stack for argument passing. */
/* use register for return : %eax */
/* no need save registers */
/* stack frame (with -pg): parent addr = 4(%ebp) */
/* child addr = (%esp) */

#include "utils/asm.h"

GLOBAL(mcount)
	sub $32, %esp
	/* save registers */
	movl %edx, 20(%esp)
	movl %ecx, 16(%esp)	
	movl %eax, 12(%esp)
	/* parent location */
	leal 4(%ebp), %eax
	movl %eax, 0(%esp)
	/* child addr */
	movl 32(%esp), %eax
	movl %eax, 4(%esp)
	/*  mcount_regs */
	leal 16(%esp), %eax
	movl %eax, 8(%esp)

	call mcount_entry

	/* restore registers */
	movl 12(%esp), %eax
	movl 16(%esp), %ecx
	movl 20(%esp), %edx
	add $32, %esp
	ret
END(mcount)


ENTRY(mcount_return)
	sub $32, %esp
	movl %edx, 12(%esp)
	movl %ecx, 8(%esp)
	movl %eax, 4(%esp)
	leal 8(%esp), %eax
	movl %eax, 0(%esp)

	/* returns original parent address */
	call mcount_exit
	movl %eax, 28(%esp)

	movl 4(%esp), %eax
	movl 8(%esp), %ecx
	movl 12(%esp), %edx
	add $28, %esp
	ret
END(mcount_return)
