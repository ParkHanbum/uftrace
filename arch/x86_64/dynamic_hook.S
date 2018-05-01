/* 
argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9 

if %rax have value bigger than 0, it means return address 
to the function have patched for dynamic tracing. 
otherwise, it must be 0 that means error occured.
*/
/* 
	stack frame : parent addr = 8(%rsp), child addr = (%rsp) 

	For example:

	Parent(caller): main()
	Child(callee): Hello()

	Dump of assembler code for function main:
	   0x00000000004005b6 <+0>:     callq  *0x20043c(%rip)        # 0x6009f8
	   0x00000000004005bc <+6>:     nop
	   0x00000000004005bd <+7>:     nop
	   0x00000000004005be <+8>:     nop
	   0x00000000004005bf <+9>:     mov    $0x400678,%edi
	   0x00000000004005c4 <+14>:    callq  0x4004a0 <dlopen@plt>
	   0x00000000004005c9 <+19>:    mov    $0x0,%eax
	   0x00000000004005ce <+24>:    callq  0x400597 <Hello>
parent	=> 0x00000000004005d3 <+29>:    mov    $0x0,%eax
	   0x00000000004005d8 <+34>:    pop    %rbp
	   0x00000000004005d9 <+35>:    retq

	Dump of assembler code for function Hello:
	   0x0000000000400597 <+0>:     callq  *0x20045b(%rip)        # 0x6009f8
child   => 0x000000000040059d <+6>:     nop
	   0x000000000040059e <+7>:     nop
	   0x000000000040059f <+8>:     movq   $0x400668,-0x8(%rbp)
	   0x00000000004005a7 <+16>:    mov    -0x8(%rbp),%rax
	   0x00000000004005ab <+20>:    mov    %rax,%rdi
	   0x00000000004005ae <+23>:    callq  0x400480 <puts@plt>
	   0x00000000004005b3 <+28>:    nop
	   0x00000000004005b4 <+29>:    leaveq
	   0x00000000004005b5 <+30>:    retq
*/

// TODO : we must fix the problem associated with following. 
// https://github.com/ParkHanbum/uftrace/issues/5


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

