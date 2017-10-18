#include "utils/asm.h"

.hidden plthook_resolver_addr

ENTRY(plt_hooker)
	sub $24, %esp
	/* save registers */
  movl %ecx, 20(%esp)
	movl %edx, 16(%esp)

	/* ret_addr */
	movl 32(%esp), %eax
	movl $eax, 0(%esp)

	/* child_idx */
	movl 28(%esp), %eax
	movl %eax, 4(%esp)
	
	/* module_id */
	movl 24(%esp), %eax
	movl %eax, 8(%esp)

	/* mcount_args */
	leal 16(%esp), %eax
	movl %eax, 12(%esp)

	call plthook_entry

	/* restore register */
	movl 20(%esp), %ecx
	movl 16(%esp), %edx

	add $24, %esp
	cmpl $0, %eax

	call 2f
	cmovz plthook_resolver_addr(%eax), %eax
	jz 1f

	add $8, %esp /* resolver function needs 2 entries on stack */
1:
	jmp *%eax
2:
	mov (%esp), %eax
	ret
END(plt_hooker)


ENTRY(plthook_return)
	sub $16, %esp
	movl %edx, 8(%esp)
	movl %eax, 4(%esp)
	leal 4(%esp), %eax
	movl %eax, 0(%esp)

	call plthook_exit
	movl %eax, 12(%esp)

	movl 4(%esp), %eax
	movl 8(%esp), %edx
	add $12, %esp
	ret
END(plthook_return)
