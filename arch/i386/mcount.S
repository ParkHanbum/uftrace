/* in i386, generally used stack for argument passing. */
/* use register for return : %eax */
/* no need save registers */
/* stack frame (with -pg): parent addr = 4(%ebp) */
/* child addr = (%esp) */

#include "utils/asm.h"

GLOBAL(mcount)
	sub $24, %esp
	movl %ecx, 20(%esp)
	movl %edx, 16(%esp)	
	/* save eax register */
	movl %eax, 12(%esp)
	/* parent location */
	leal 4(%ebp), %eax
	movl %eax, 0(%esp)
	/* child addr */
	movl 24(%esp), %eax
	movl %eax, 4(%esp)
	/*  mcount_regs */
	leal 16(%esp), %eax
	movl %eax, 8(%esp)

	call mcount_entry
	cmpl $0, %eax

	/* restore eax register */
	movl 12(%esp), %eax
	add $24, %esp
	ret
END(mcount)


ENTRY(mcount_return)
	sub $16, %esp
	movl %edx, 4(%esp)
	movl %eax, 0(%esp)

	/* returns original parent address */
	call mcount_exit
	movl %eax, 12(%esp)

	movl 0(%esp), %eax
	movl 4(%esp), %edx
	add $12, %esp
	ret
END(mcount_return)
