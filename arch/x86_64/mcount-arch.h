#ifndef MCOUNT_ARCH_H
#define MCOUNT_ARCH_H

#include "utils/arch.h"
#include "utils/list.h"

#define mcount_regs  mcount_regs

struct mcount_regs {
	unsigned long  r9;
	unsigned long  r8;
	unsigned long  rcx;
	unsigned long  rdx;
	unsigned long  rsi;
	unsigned long  rdi;
};

#define  ARG1(a)  ((a)->rdi)
#define  ARG2(a)  ((a)->rsi)
#define  ARG3(a)  ((a)->rdx)
#define  ARG4(a)  ((a)->rcx)
#define  ARG5(a)  ((a)->r8)
#define  ARG6(a)  ((a)->r9)

#define ARCH_MAX_REG_ARGS  6
#define ARCH_MAX_FLOAT_REGS  8

#define HAVE_MCOUNT_ARCH_CONTEXT
struct mcount_arch_context {
	double xmm[ARCH_MAX_FLOAT_REGS];
};

#define ARCH_PLT0_SIZE  16
#define ARCH_PLTHOOK_ADDR_OFFSET  6

#define ARCH_SUPPORT_AUTO_RECOVER  1
#define ARCH_CAN_RESTORE_PLTHOOK   1

struct plthook_arch_context {
	bool	has_plt_sec;
};

struct mcount_disasm_engine;
struct mcount_dynamic_info;
struct mcount_disasm_info;
struct sym;

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info);

struct user_regs_struct {
	unsigned long long int r15;
	unsigned long long int r14;
	unsigned long long int r13;
	unsigned long long int r12;
	unsigned long long int rbp;
	unsigned long long int rbx;
	unsigned long long int r11;
	unsigned long long int r10;
	unsigned long long int r9;
	unsigned long long int r8;
	unsigned long long int rax;
	unsigned long long int rcx;
	unsigned long long int rdx;
	unsigned long long int rsi;
	unsigned long long int rdi;
	unsigned long long int orig_rax;
	unsigned long long int rip;
	unsigned long long int cs;
	unsigned long long int eflags;
	unsigned long long int rsp;
	unsigned long long int ss;
	unsigned long long int fs_base;
	unsigned long long int gs_base;
	unsigned long long int ds;
	unsigned long long int es;
	unsigned long long int fs;
	unsigned long long int gs;
};

#define ARCH_REGS	struct user_regs_struct
#define ARCH_PC_TYPE	typeof(((ARCH_REGS *)0)->rip)

inline ARCH_PC_TYPE get_pc(ARCH_REGS regs)
{
	return regs.rip;
}

inline void set_pc(ARCH_REGS *regs, ARCH_PC_TYPE pc)
{
	regs->rip = pc;
}

#endif /* MCOUNT_ARCH_H */
