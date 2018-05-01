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
	sub $128, %rsp
	.cfi_adjust_cfa_offset 56

	movq %rax, 120(%rsp)
	movq %rcx, 112(%rsp)
	movq %rdx, 104(%rsp)
	movq %rbx, 96(%rsp)
#	movq %rsp, 88(%rsp)
	movq %rbp, 80(%rsp)
	movq %rsi, 72(%rsp)
	movq %rdi, 64(%rsp)
	movq %r8, 56(%rsp)
	movq %r9, 48(%rsp)
	movq %r10, 40(%rsp)
	movq %r11, 32(%rsp)
	movq %r12, 24(%rsp)
	movq %r13, 16(%rsp)
	movq %r14, 8(%rsp)
	movq %r15, 0(%rsp)

	/* child addr */
	movq 128(%rsp), %rsi
	/* parent location */
	lea 136(%rsp), %rdi

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
	movq %rax, 128(%rsp)
		
	/* hijack return address */
	movabs $dentry_return@GOTOFF, %rdx
	lea _GLOBAL_OFFSET_TABLE_(%rip), %rcx
	add %rcx, %rdx
	movq %rdx, 136(%rsp)
1:
	movq 120(%rsp), %rax
	movq 112(%rsp), %rcx
	movq 104(%rsp), %rdx
	movq 96(%rsp), %rbx
#	movq 88(%rsp), %rsp
	movq 80(%rsp), %rbp
	movq 72(%rsp), %rsi
	movq 64(%rsp), %rdi
	movq 56(%rsp), %r8
	movq 48(%rsp), %r9
	movq 40(%rsp), %r10
	movq 32(%rsp), %r11
	movq 24(%rsp), %r12
	movq 16(%rsp), %r13
	movq 8(%rsp), %r14
	movq 0(%rsp), %r15

	add $128, %rsp
	.cfi_adjust_cfa_offset -48

	retq
	.cfi_endproc
END(__dentry__)


ENTRY(dentry_return)
	sub $136, %rsp

	movq %r15, 120(%rsp)
	movq %rcx, 112(%rsp)
	movq %r14, 104(%rsp)
	movq %rbx, 96(%rsp)
#	movq %rsp, 88(%rsp)
	movq %rbp, 80(%rsp)
	movq %rsi, 72(%rsp)
	movq %rdi, 64(%rsp)
	movq %r8, 56(%rsp)
	movq %r9, 48(%rsp)
	movq %r10, 40(%rsp)
	movq %r11, 32(%rsp)
	movq %r12, 24(%rsp)
	movq %r13, 16(%rsp)
	movq %rdx, 8(%rsp)
	movq %rax, 0(%rsp)

	/* set the first argument of mcount_exit as pointer to return values */
	movq %rsp, %rdi

	/* returns original parent address */
	call mcount_exit
	movq %rax, 128(%rsp)

	movq 120(%rsp), %r15
	movq 112(%rsp), %rcx
	movq 104(%rsp), %r14
	movq 96(%rsp), %rbx
#	movq 88(%rsp), %rsp
	movq 80(%rsp), %rbp
	movq 72(%rsp), %rsi
	movq 64(%rsp), %rdi
	movq 56(%rsp), %r8
	movq 48(%rsp), %r9
	movq 40(%rsp), %r10
	movq 32(%rsp), %r11
	movq 24(%rsp), %r12
	movq 16(%rsp), %r13
	movq 8(%rsp), %rdx
	movq 0(%rsp), %rax

	add $128, %rsp
	retq
END(dentry_return)

