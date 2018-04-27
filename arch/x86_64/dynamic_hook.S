#include "utils/asm.h"

GLOBAL(__dentry__)
	.cfi_startproc
	/*
	 * 48 is needed because of the 16-byte
	 * stack alignment required from GCC7
	 */
	sub $48, %rsp
	.cfi_adjust_cfa_offset 48

	movq %rdi, 40(%rsp)
	.cfi_offset rdi, -24
	movq %rsi, 32(%rsp)
	.cfi_offset rsi, -32
	movq %rdx, 24(%rsp)
	.cfi_offset rdx, -40
	movq %rcx, 16(%rsp)
	.cfi_offset rcx, -48
	movq %r8, 8(%rsp)
	.cfi_offset r8, -56
	movq %r9, 0(%rsp)
	.cfi_offset r9, -64

	/* child addr */
	movq 48(%rsp), %rsi
	/* parent location */
	lea 56(%rsp), %rdi

	/* mcount_args */
	movq %rsp, %rdx

	/* 
	dynamic_entry returns the address 
	holding the patched original code.
	*/
	call dynamic_entry
	cmpq $0, %rax
	jz 1f

	/*
	return address will be replaced with	
	saved original code chunk address.
	*/
	movq %rax, 48(%rsp)
		
	/* hijack return address */
	movabs $dentry_return@GOTOFF, %rdx
	lea _GLOBAL_OFFSET_TABLE_(%rip), %rcx
	add %rcx, %rdx
	movq %rdx, 56(%rsp)
1:
	movq 0(%rsp), %r9
	movq 8(%rsp), %r8
	movq 16(%rsp), %rcx
	movq 24(%rsp), %rdx
	movq 32(%rsp), %rsi
	movq 40(%rsp), %rdi

	add $48, %rsp
	.cfi_adjust_cfa_offset -48

	retq
	.cfi_endproc
END(__dentry__)


ENTRY(dentry_return)
	.cfi_startproc
	sub  $32, %rsp
	.cfi_def_cfa_offset 32

	movq %rdx, 8(%rsp)
	.cfi_offset rdx, -24
	movq %rax, 0(%rsp)
	.cfi_offset rax, -32

	/* set the first argument of mcount_exit as pointer to return values */
	movq %rsp, %rdi

	/* returns original parent address */
	call mcount_exit
	movq %rax, 24(%rsp)

	movq 0(%rsp), %rax
	movq 8(%rsp), %rdx

	add  $24, %rsp
	.cfi_def_cfa_offset 24

	retq
	.cfi_endproc
END(dentry_return)

