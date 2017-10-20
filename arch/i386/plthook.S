#include "utils/asm.h"

.hidden plthook_resolver_addr

ENTRY(plt_hooker)
	sub $32, %esp
	/* save registers */
	movl %edx, 20(%esp)
	movl %ecx, 16(%esp)

	/* stack address contain parent location */
	leal 40(%esp), %eax
	movl %eax, 0(%esp)

	/* child_idx */
	movl 36(%esp), %eax
	movl %eax, 4(%esp)
	
	/* module_id */
	movl 32(%esp), %eax
	movl %eax, 8(%esp)

	/* mcount_args */
	leal 16(%esp), %eax
	movl %eax, 12(%esp)

	call plthook_entry

	/* restore registers */
	movl 16(%esp), %ecx
	movl 20(%esp), %edx
	add $32, %esp

	cmpl $0, %eax
	jnz 1f
	/* get address of plthook_resolver_addr */
	call __x86.get_pc_thunk.ax
	addl $_GLOBAL_OFFSET_TABLE_, %eax
	leal plthook_resolver_addr@GOTOFF(%eax), %eax
	movl (%eax), %eax
	jmp *%eax
1:
	add $8, %esp
	jmp *%eax
END(plt_hooker)


ENTRY(plthook_return)
	sub $32, %esp
	movl %edx, 12(%esp)
	movl %ecx, 8(%esp)
	movl %eax, 4(%esp)

	leal 8(%esp), %eax
	movl %eax, 0(%esp)

	call plthook_exit
	movl %eax, 28(%esp)

	movl 4(%esp), %eax
	movl 8(%esp), %ecx
	movl 12(%esp), %edx
	add $28, %esp
	ret
END(plthook_return)
