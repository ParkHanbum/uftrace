#include <assert.h>
#include <string.h>
#include <gelf.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/internal.h"
#include "utils/filter.h"

void mcount_get_arg(struct mcount_arg_context *ctx,
			  struct uftrace_arg_spec *spec)
{
	struct mcount_regs *regs = ctx->regs;
	int reg_idx;
	int offset;

	switch (spec->type) {
		case ARG_TYPE_STACK:
			offset = spec->stack_ofs;
			break;
		case ARG_TYPE_INDEX:
			offset = spec->idx;
			break;
		case ARG_TYPE_FLOAT:
			offset = spec->idx;
			break;
		case ARG_TYPE_REG:
			reg_idx = spec->reg_idx;
			break;
		default:
			/* should not reach here */
			pr_err_ns("invalid stack access for arguments\n");
			break;
	}

	if (spec->type == ARG_TYPE_REG) {
		switch (reg_idx) {
			case X86_REG_ECX:
				ctx->val.i = ARG1(regs);
				break;
			case X86_REG_EDX:
				ctx->val.i = ARG2(regs);
				break;
			case X86_REG_XMM0:
				asm volatile ("movsd %%xmm0, %0\n" : "=m" (ctx->val.v));
				break;
			case X86_REG_XMM1:
				asm volatile ("movsd %%xmm1, %0\n" : "=m" (ctx->val.v));
				break;
			case X86_REG_XMM2:
				asm volatile ("movsd %%xmm2, %0\n" : "=m" (ctx->val.v));
				break;
			case X86_REG_XMM3:
				asm volatile ("movsd %%xmm3, %0\n" : "=m" (ctx->val.v));
				break;
			case X86_REG_XMM4:
				asm volatile ("movsd %%xmm4, %0\n" : "=m" (ctx->val.v));
				break;
			case X86_REG_XMM5:
				asm volatile ("movsd %%xmm5, %0\n" : "=m" (ctx->val.v));
				break;
			case X86_REG_XMM6:
				asm volatile ("movsd %%xmm6, %0\n" : "=m" (ctx->val.v));
				break;
			case X86_REG_XMM7:
				asm volatile ("movsd %%xmm7, %0\n" : "=m" (ctx->val.v));
				break;
			default:
				/* should not reach here */
				pr_err_ns("invalid register access for arguments\n");
				break;
		}
	}

	if (offset < 1 || offset > 100)
		pr_dbg("invalid stack offset: %d\n", offset);

	memcpy(ctx->val.v, ctx->stack_base + offset, spec->size);
}

void mcount_arch_get_arg(struct mcount_arg_context *ctx,
			 struct uftrace_arg_spec *spec)
{
	mcount_get_arg(ctx, spec);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx,
			    struct uftrace_arg_spec *spec)
{
	/* type of return value cannot be FLOAT, so check format instead */
	if (spec->fmt != ARG_FMT_FLOAT)
		memcpy(ctx->val.v, ctx->retval, spec->size);
	else if (spec->size == 4)  
		asm volatile ("fstps %0\n\tflds %0" : "=m" (ctx->val.v));
    else if (spec->size == 8)
        asm volatile ("fstpl %0\n\tfldl %0" : "=m" (ctx->val.v));
}

void mcount_save_arch_context(struct mcount_arch_context *ctx)
{
	asm volatile ("movsd %%xmm0, %0\n" : "=m" (ctx->xmm[0]));
	asm volatile ("movsd %%xmm1, %0\n" : "=m" (ctx->xmm[1]));
	asm volatile ("movsd %%xmm2, %0\n" : "=m" (ctx->xmm[2]));
	asm volatile ("movsd %%xmm3, %0\n" : "=m" (ctx->xmm[3]));
	asm volatile ("movsd %%xmm4, %0\n" : "=m" (ctx->xmm[4]));
	asm volatile ("movsd %%xmm5, %0\n" : "=m" (ctx->xmm[5]));
	asm volatile ("movsd %%xmm6, %0\n" : "=m" (ctx->xmm[6]));
	asm volatile ("movsd %%xmm7, %0\n" : "=m" (ctx->xmm[7]));
}

void mcount_restore_arch_context(struct mcount_arch_context *ctx)
{
	asm volatile ("movsd %0, %%xmm0\n" :: "m" (ctx->xmm[0]));
	asm volatile ("movsd %0, %%xmm1\n" :: "m" (ctx->xmm[1]));
	asm volatile ("movsd %0, %%xmm2\n" :: "m" (ctx->xmm[2]));
	asm volatile ("movsd %0, %%xmm3\n" :: "m" (ctx->xmm[3]));
	asm volatile ("movsd %0, %%xmm4\n" :: "m" (ctx->xmm[4]));
	asm volatile ("movsd %0, %%xmm5\n" :: "m" (ctx->xmm[5]));
	asm volatile ("movsd %0, %%xmm6\n" :: "m" (ctx->xmm[6]));
	asm volatile ("movsd %0, %%xmm7\n" :: "m" (ctx->xmm[7]));
}

#define R_OFFSET_POS  2
#define PUSH_IDX_POS  1
#define JMP_OFS_POS   7
#define JMP_INSN_SIZE 6
#define PLTGOT_SIZE   8
#define PAD_SIZE      5

int mcount_arch_undo_bindnow(Elf *elf, struct plthook_data *pd)
{
	unsigned idx;
	int got_idx;
	struct sym *sym;
	struct symtab *dsymtab;
	unsigned r_offset;
	unsigned long r_addr;
	unsigned long real_addr;
	unsigned long plt_addr = 0;
	bool has_rela_plt = false;
	unsigned long pltgot_addr = (unsigned long)pd->pltgot_ptr;
	void *target_addr;
	unsigned jump_offset;
	void *trampoline_buf;
	size_t i, trampoline_size;
	unsigned char trampoline[] = {
		0x68, 0x00, 0x00, 0x00, 0x00,        /* push $idx */
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,  /* jmp *(offset) */
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc,        /* padding */
	};
	Elf_Scn *sec;
	const char *skip_syms[] = {
		"mcount", "__fentry__",
		"__cyg_profile_func_enter", "__cyg_profile_func_exit",
		"__cxa_finalize",  /* XXX: it caused segfault */
		"__gmon_start__",  /* XXX: it makes process stuck */
	};
	size_t shstr_idx;

	dsymtab = &pd->dsymtab;

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		return -1;

	sec = NULL;
	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		GElf_Shdr shdr;
		char *shname;

		if (gelf_getshdr(sec, &shdr) == NULL)
			return -1;

		shname = elf_strptr(elf, shstr_idx, shdr.sh_name);
		if (!strcmp(shname, ".plt"))
			plt_addr = shdr.sh_addr + pd->base_addr;
		if (!strcmp(shname, ".rela.plt"))
			has_rela_plt = true;
	}

	if (plt_addr == 0) {
		pr_dbg("cannot find PLT address\n");
		return -1;
	}

	if (has_rela_plt) {
		/* it's already handled by restore_plt_functions() in find_got() */
		return 0;
	}

	trampoline_size = (dsymtab->nr_sym + 1) * sizeof(trampoline);
	trampoline_buf = mmap(0, trampoline_size, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (trampoline_buf == MAP_FAILED)
		pr_err("failed to mmap trampoline for bind now");

	pr_dbg2("setup bind-now PLT trampoline at %#lx\n", trampoline_buf);

	for (idx = 0; idx < dsymtab->nr_sym; idx++) {
		sym = dsymtab->sym_names[idx];

		for (i = 0; i < ARRAY_SIZE(skip_syms); i++) {
			if (!strcmp(sym->name, skip_syms[i]))
				break;
		}
		if (i != ARRAY_SIZE(skip_syms))
			continue;

		memcpy(&r_offset, (void *)sym->addr + R_OFFSET_POS, sizeof(r_offset));
		r_addr = r_offset + sym->addr + JMP_INSN_SIZE;

		/* GOT index can be different than the symbol index */
		got_idx = (r_addr - pltgot_addr) / sizeof(long);

		target_addr = trampoline_buf + (idx * sizeof(trampoline));
		real_addr = setup_pltgot(pd, got_idx, idx, target_addr);

		jump_offset = (dsymtab->nr_sym - idx - 1) * sizeof(trampoline) + PAD_SIZE;

		pr_dbg3("[%d] %s got idx %d, r_offset %lx, real address = %#lx, "
			"target addr = %p, jump offset = %#lx\n",
			idx, sym->name, got_idx, r_offset + sym->addr - pd->base_addr + JMP_INSN_SIZE,
			real_addr, target_addr, jump_offset);

		/* make up the instruction and copy to the trampoline buffer */
		memcpy(&trampoline[PUSH_IDX_POS], &idx, sizeof(idx));
		memcpy(&trampoline[JMP_OFS_POS], &jump_offset, sizeof(jump_offset));
		memcpy(target_addr, trampoline, sizeof(trampoline));
	}

	pr_dbg2("real address to jump: %#lx\n", plt_addr);
	memcpy(trampoline_buf + (idx * sizeof(trampoline)),
	       &plt_addr, sizeof(plt_addr));

	mprotect(trampoline_buf, trampoline_size, PROT_READ | PROT_EXEC);
	return 0;
}

unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx)
{
	struct sym *sym;

	sym = &pd->dsymtab.sym[idx];
	return sym->addr;
}


/*
	For 16-byte stack-alignment, 
	the main function stores the return address in its stack scope at prologue.
	When the time comes for the main function to return,
	1. restore the saved return address from stack.
	2. After cleaning up the stack.
	3. Put the return address at the top of the stack and return.
	4. will be returned.

	080485f8 <main>:
	80485f8: 8d 4c 24 04           lea    0x4(%esp),%ecx
	80485fc: 83 e4 f0              and    $0xfffffff0,%esp
	80485ff: ff 71 fc              pushl  -0x4(%ecx)
	8048602: 55                    push   %ebp
	8048603: 89 e5                 mov    %esp,%ebp
	8048605: 51                    push   %ecx
	8048606: 83 ec 14              sub    $0x14,%esp
	8048609: e8 02 fe ff ff        call   8048410 <mcount@plt>

	... ... 

	8048645: 8b 4d fc              mov    -0x4(%ebp),%ecx
	8048648: c9                    leave
	8048649: 8d 61 fc              lea    -0x4(%ecx),%esp
	804864c: c3                    ret

	So, in this case. The return address we want to replace with 
	mcount_exit is in the stack scope of the main function. 
	Non a parent located. 

	we search stack for that address. 
	we will look for it.
	we will find it, and we will replace it. 
	GOOD LUCK!
*/
unsigned long *mcount_arch_parent_location(struct symtabs *symtabs,
										             unsigned long *parent_loc, 
																 unsigned long child_ip)
{
	struct sym *parent_sym, *child_sym;
	char *pname, *cname;

	const char *find_main[] = {
		"__libc_start_main",
		"main"
	};
	unsigned long ret_addr;
	unsigned long search_ret_addr;

	pr_dbg("FIND SYMBOL\n");
	ret_addr = *parent_loc;
	parent_sym = find_symtabs(symtabs, ret_addr);
	pname = symbol_getname(parent_sym, ret_addr);
	pr_dbg("SYMBOL : %s\n", pname);
	pr_dbg("FIND CHILD SYMBOL\n");
	child_sym = find_symtabs(symtabs, child_ip);
	cname = symbol_getname(child_sym, child_ip);
	pr_dbg("SYMBOL : %s\n", cname);
	
	// Assuming that this happens only in main.			
	if (!strcmp(find_main[0], pname)) {
		if (!strcmp(find_main[1], cname)) {
			ret_addr = *parent_loc;
			pr_dbg("FIND RET ADDRESS : %llu\n", ret_addr);
			for (int i = 1; i < 5; i++ ) {
				search_ret_addr = *(unsigned long *)(parent_loc + i);
				pr_dbg("SEARCHING RET ADDRESS : %llu\n", search_ret_addr);
				if (search_ret_addr == ret_addr) {
					parent_loc = parent_loc+i;
					pr_dbg("MATCH RET ADDRESS : %llu\n", parent_loc);
				}
			}
		} // cname 
	} // pname
	return parent_loc;
}
