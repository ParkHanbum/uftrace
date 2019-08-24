#include "libmcount/internal.h"
#include "mcount-arch.h"

#define CALL_INSN_SIZE  5

#ifdef HAVE_LIBCAPSTONE
#include <capstone/capstone.h>
#include <capstone/platform.h>

struct disasm_check_data {
	uintptr_t		addr;
	uint32_t		func_size;
	uint32_t		patch_size;
	uint32_t		copy_size;
	uint32_t		size;
};

void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &disasm->engine) != CS_ERR_OK) {
		pr_dbg("failed to init Capstone disasm engine\n");
		return;
	}

	if (cs_option(disasm->engine, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		pr_dbg("failed to set detail option\n");
}

void mcount_disasm_finish(struct mcount_disasm_engine *disasm)
{
	cs_close(&disasm->engine);
}

/*
 * check whether the instruction can be executed regardless of its location.
 * returns false when instructions are not suitable for dynamic patch.
 *
 * TODO: this function is incomplete and need more classification.
 */
// define reasons that cause fail to instrument.
#define INSTRUMENT_FAIL_UNKNOWN		0x00000001L
#define INSTRUMENT_FAIL_NOOPRND		0x00000001L << 1L
#define INSTRUMENT_FAIL_RELJMP		0x00000001L << 2L
#define INSTRUMENT_FAIL_RELCALL		0x00000001L << 3L
#define INSTRUMENT_FAIL_PICCODE		0x00000001L << 4L

#define OP_GROUP_JMP			1
#define OP_GROUP_CALL			2

const char* instrument_fail_msg(int reason)
{
	const char *res = "UNKNOWN";
	switch(reason) {
		case INSTRUMENT_FAIL_NOOPRND:
			res = "Not supported opcode without operand";
			break;
		case INSTRUMENT_FAIL_RELJMP:
			res = "Not supported opcode that jump to relative address";
			break;
		case INSTRUMENT_FAIL_RELCALL:
			res = "Not supported opcode that call to relative address";
			break;
		case INSTRUMENT_FAIL_PICCODE:
			res = "Not supported Position Independent Code";
			break;
	}

	return res;
}

static int check_instrumentable(struct mcount_disasm_engine *disasm,
				 cs_insn *insn)
{
	int i;
	cs_x86 *x86;
	cs_detail *detail;
	int jmp_or_call = 0;
	int status = 0;

	/*
	 * 'detail' can be NULL on "data" instruction
	 * if SKIPDATA option is turned ON
	 */
	if (insn->detail == NULL) {
		status = INSTRUMENT_FAIL_UNKNOWN;
		goto out;
	}

	detail = insn->detail;

	for (i = 0; i < detail->groups_count; i++) {
		if (detail->groups[i] == CS_GRP_CALL)
			jmp_or_call = OP_GROUP_CALL;
		else if (detail->groups[i] == CS_GRP_JUMP)
			jmp_or_call = OP_GROUP_JMP;
	}

	x86 = &insn->detail->x86;

	if (!x86->op_count)
		goto out;

	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &x86->operands[i];

		switch((int)op->type) {
			case X86_OP_REG:
				continue;

			case X86_OP_IMM:
				if (jmp_or_call > 0) {
					if (jmp_or_call == OP_GROUP_CALL)
						status = INSTRUMENT_FAIL_RELCALL;
					else
						status = INSTRUMENT_FAIL_RELJMP;
					goto out;
				}
				continue;

			case X86_OP_MEM:
				if (op->mem.base == X86_REG_RIP ||
				    op->mem.index == X86_REG_RIP) {
					status = INSTRUMENT_FAIL_PICCODE;
					goto out;
				}
				continue;
			default:
				continue;
		}
	}

out:
	if (status > 0)
		pr_dbg3("Could not instrument, Reason : %s\n", instrument_fail_msg(status));
	else
		pr_dbg3("Patched Instr : \n");

	return status;
}

static bool check_unsupported(struct mcount_disasm_engine *disasm, cs_insn *insn,
			      struct mcount_dynamic_info *mdi,
			      struct disasm_check_data *insn_check)
{
	int i;
	cs_x86 *x86;
	cs_detail *detail = insn->detail;
	unsigned long target;
	bool jump = false;

	if (detail == NULL)
		return false;

	detail = insn->detail;

	/* assume there's no call into the middle of function */
	for (i = 0; i < detail->groups_count; i++) {
		if (detail->groups[i] == CS_GRP_JUMP)
			jump = true;
	}

	if (!jump)
		return true;

	x86 = &insn->detail->x86;
	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &x86->operands[i];

		switch((int)op->type) {
		case X86_OP_IMM:
			/* capstone seems already calculate target address */
			target = op->imm;

			/* disallow (back) jump to the prologue */
			if (insn_check->addr <= target &&
			    target < insn_check->addr + insn_check->size)
				return false;

			/* disallow jump to middle of other function */
			if (insn_check->addr > target ||
			    target >= insn_check->addr + insn_check->func_size) {
				/* also mark the target function as invalid */
				return !add_bad_jump(mdi, insn->address, target);
			}
			break;
		case X86_OP_MEM:
			/* indirect jumps are not allowed */
			return false;
			break;
		case X86_OP_REG:
			return false;
		default:
			break;
		}
	}

	return true;
}

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi, struct sym *sym)
{
	cs_insn *insn = NULL;
	uint32_t count, i;
	uint8_t endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };
	int ret = INSTRUMENT_FAILED;
	struct disasm_check_data insn_check = {
		.addr		= sym->addr + mdi->map->start,
		.func_size	= sym->size,
	};
	struct dynamic_bad_symbol *badsym;

	badsym = find_bad_jump(mdi, insn_check.addr);
	if (badsym != NULL) {
		list_del(&badsym->list);
		free(badsym);
		return ret;
	}

	count = cs_disasm(disasm->engine, (void *)insn_check.addr, sym->size,
			  insn_check.addr, 0, &insn);
	if (unlikely(count == 0) &&
	    !memcmp((void *)insn_check.addr, endbr64, sizeof(endbr64))) {
		/* old version of capstone doesn't recognize ENDBR64 insn */
		insn_check.addr += sizeof(endbr64);
		insn_check.func_size -= sizeof(endbr64);
		insn_check.copy_size += sizeof(endbr64);

		count = cs_disasm(disasm->engine, (void *)insn_check.addr,
				  insn_check.func_size, insn_check.addr,
				  insn_check.addr, &insn);
	}

	for (i = 0; i < count; i++) {
		if (check_instrumentable(disasm, &insn[i]) > 0) {
			pr_dbg3("not supported instruction found at %s : %s\t %s\n",
				sym->name, insn[i].mnemonic, insn[i].op_str);
			goto out;
		}

		insn_check.copy_size += insn[i].size;
		if (insn_check.copy_size >= CALL_INSN_SIZE) {
			ret = insn_check.copy_size;
			break;
		}
	}

	while (++i < count) {
		if (!check_unsupported(disasm, &insn[i], mdi, &insn_check)) {
			ret = INSTRUMENT_FAILED;
			break;
		}
	}
out:
	if (count)
		cs_free(insn, count);

	return ret;
}

#else /* HAVE_LIBCAPSTONE */

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi, struct sym *sym)
{
	return INSTRUMENT_FAILED;
}

#endif /* HAVE_LIBCAPSTONE */
