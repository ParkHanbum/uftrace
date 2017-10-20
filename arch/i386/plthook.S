#include "utils/asm.h"

.hidden plthook_resolver_addr

ENTRY(plt_hooker)
	sub $24, %esp
	/* save registers */
  movl %edx, 20(%esp)
	movl %ecx, 16(%esp)
	/* stack address contain parent location - arg1 */
	leal 32(%esp), %eax
	movl %eax, 0(%esp)
	/* child_idx - arg2 */
	movl 28(%esp), %eax
	movl %eax, 4(%esp)
	/* module_id - arg3 */
	movl 24(%esp), %eax
	movl %eax, 8(%esp)
	/* mcount_args - arg4*/
	leal 16(%esp), %eax
	movl %eax, 12(%esp)

	call plthook_entry

	/* restore register */
	movl 16(%esp), %ecx
	movl 20(%esp), %edx
	add $24, %esp

	/* get address of plthook_resolver_addr */
	call __x86.get_pc_thunk.ax
#	call get_pc
	addl $_GLOBAL_OFFSET_TABLE_, %eax
	leal plthook_resolver_addr@GOTOFF(%eax), %eax
	jmp *(%eax)
END(plt_hooker)


ENTRY(plthook_return)
	sub $16, %esp
	movl %edx, 8(%esp)
	movl %ecx, 4(%esp)
	leal 4(%esp), %eax
	movl %eax, 0(%esp)

	call plthook_exit
	movl %eax, 12(%esp)

	movl 4(%esp), %ecx
	movl 8(%esp), %edx
	add $12, %esp
	ret
END(plthook_return)
