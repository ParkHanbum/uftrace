#ifndef MCOUNT_CPU_H
#define MCOUNT_CPU_H

enum x86_reg_index {
	X86_REG_INT_BASE = 0,
	/* integer registers */
	X86_REG_RDI,
	X86_REG_RSI,
	X86_REG_RDX,
	X86_REG_RCX,
	X86_REG_R8,
	X86_REG_R9,

	X86_REG_FLOAT_BASE = 100,
	/* floating-point registers */
	X86_REG_XMM0,
	X86_REG_XMM1,
	X86_REG_XMM2,
	X86_REG_XMM3,
	X86_REG_XMM4,
	X86_REG_XMM5,
	X86_REG_XMM6,
	X86_REG_XMM7,
};

#endif
