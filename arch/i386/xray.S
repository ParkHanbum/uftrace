/* argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9 */
/* return value: %rax */
/* callee saved: %rbx, %rbp, %rsp, %r12-r15 */
/* stack frame: child addr = 0(%rsp), return addr = 8(%rbp) */

#include "utils/asm.h"

GLOBAL(__xray_entry)
	sub $32, %esp
	movl %edx, 24(%esp)
	movl %ecx, 20(%esp)
	movl $0, 16(%esp)
	
	/* stack address contain parent location */
	leal 36(%esp), %eax
	movl %eax, 0(%esp)
	/* child ip */
	movl 32(%esp), %eax
	movl %eax, 4(%esp)

	/* mcount_args */
	leal 16(%esp), %eax
	movl %eax, 8(%esp)
	
	call xray_entry

	movl 20(%esp), %ecx
	movl 24(%esp), %edx

	add $32, %esp
	ret

GLOBAL(__xray_exit)
	sub $16, %esp
	movl %edx, 8(%esp)
	movl %eax, 4(%esp)

	leal 4(%esp), %eax
	movl %eax, 0(%esp)

	call xray_exit

	movl 4(%esp), %eax
	movl 8(%esp), %edx
	add $16, %esp
	ret
