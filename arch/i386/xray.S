/* argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9 */
/* return value: %rax */
/* callee saved: %rbx, %rbp, %rsp, %r12-r15 */
/* stack frame: child addr = 0(%rsp), return addr = 8(%rbp) */

#include "utils/asm.h"

GLOBAL(__xray_entry)
	sub $24, %esp
	movl %edx, 20(%esp)
	movl %ecx, 16(%esp)
	movl %eax, 12(%esp)
	
	/* stack address contain parent location */
	leal 28(%esp), %eax
	movl %eax, 0(%esp)
	/* child ip */
	movl 24(%esp), %eax
	movl %eax, 4(%esp)

	/* mcount_args */
	leal 16(%esp), %eax
	movl %eax, 8(%esp)
	
	call xray_entry

	movl 12(%esp), %eax
	movl 16(%esp), %ecx
	movl 20(%esp), %edx

	add $24, %esp
	ret

GLOBAL(__xray_exit)
	sub $16, %esp
	movl %edx, 12(%esp)
	movl %ecx, 8(%esp)
	movl %eax, 4(%esp)

	leal 8(%esp), %eax
	movl %eax, 0(%esp)

	call xray_exit

	movl 4(%esp), %eax
	movl 8(%esp), %ecx
	movl 12(%esp), %edx

	add $16, %esp
	ret
