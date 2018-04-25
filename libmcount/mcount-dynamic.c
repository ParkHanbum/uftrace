/*
 * mcount() handling routines for uftrace
 *
 * Copyright (C) 2014-2017, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <signal.h>

/* include for using capstone */
#include <inttypes.h>
#include <capstone/capstone.h>
#include <capstone/platform.h>
/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/script.h"
#include "utils/debugger.h"

extern void mtd_dtor(void *arg);

#define SETRWX(addr, len)   mprotect((void*)((addr) &~ 0xFFF),\
                                     (len) + ((addr) - ((addr) &~ 0xFFF)),\
                                     PROT_READ | PROT_EXEC | PROT_WRITE)
#define SETROX(addr, len)   mprotect((void*)((addr) &~ 0xFFF),\
                                     (len) + ((addr) - ((addr) &~ 0xFFF)),\
                                     PROT_READ | PROT_EXEC)

extern void fentry_return(void);
extern unsigned long plthook_resolver_addr;

// TODO : conform with feature
// 0 of pltgot_addr is replaced with record function. 
extern unsigned long pltgot_addr;

// to keeping address _start function.
static unsigned long _start_addr = 0;

// call relative address 
// there is no instruction to jumping 64bit address directly.
static unsigned char g_call_insn[] =  
{0xFF, 0x15, 0x00, 0x00, 0x00, 0x00};

static unsigned char g_jmp_insn[] = 
{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};

static const int instruction_size = sizeof(g_call_insn); 

csh csh_handle;
extern cs_err cs_open(cs_arch arch, cs_mode mode, csh *handle);

typedef unsigned char* puchar;

static void print_string_hex(char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

void print_disassemble(uintptr_t address, uint32_t size) 
{
	cs_insn *insn;
	int code_size = 0;
	int count = cs_disasm(csh_handle, (unsigned char*)address, size, address, 0, &insn);
	pr_dbg("DISASM:\n");
	int j;
	for(j = 0;j < count;j++) {
		pr_dbg("0x%"PRIx64"[%02d]:%s %s\n", insn[j].address, insn[j].size, insn[j].mnemonic, insn[j].op_str);
	}
	
	cs_free(insn, count);	
}

puchar patch_code(uintptr_t addr, unsigned char* call_insn, unsigned int code_size) 
{
	// calc relative address of addr between pltgot_addr;
	unsigned long rel_addr = pltgot_addr - addr - instruction_size;
	puchar ptr = &rel_addr;
	puchar save_addr, code_addr;
	// expand code_size to include return instruction.
	uint32_t saved_code_size = code_size + sizeof(g_jmp_insn) + sizeof(long);
	int i;

	// make instruction to patch. 	
	for(i=0;i < 4;i++) {
		pr_dbg2("%02x\n", *(ptr+i));
		call_insn[2 + i] = *(ptr+i); // FF 15 XX XX XX XX 
	}
	print_string_hex("INSTRUMENT INSTRUCTION : ", call_insn, instruction_size);

	uintptr_t alloc_addr = malloc(saved_code_size);	
	memset(alloc_addr, NULL, saved_code_size); 
	SETRWX(alloc_addr, saved_code_size);

	save_addr = (puchar)alloc_addr;
	code_addr = (puchar)addr;

	// patch the code!!
	for(i=0;i < code_size;i++) {
		save_addr[i] = code_addr[i];
		if (i > instruction_size-1) {
			pr_dbg2("patching... : %x to %x \n", code_addr[i], 0x90);
			code_addr[i] = 0x90; 
		} else {
			pr_dbg2("patching... : %x to %x \n", code_addr[i], call_insn[i]);
			code_addr[i] = call_insn[i];	
		}
	}
	
	// inject jump to return origin 
	save_addr[code_size+0] = g_jmp_insn[0];
	save_addr[code_size+1] = g_jmp_insn[1];
	save_addr[code_size+2] = g_jmp_insn[2];
	save_addr[code_size+3] = g_jmp_insn[3];
	save_addr[code_size+4] = g_jmp_insn[4];
	save_addr[code_size+5] = g_jmp_insn[5];

	*((uintptr_t *)(&save_addr[code_size+6])) = &code_addr[code_size];
	pr_dbg2("RETURN ADDRESS : %llx\n", &code_addr[code_size]);
	
	print_disassemble(save_addr, saved_code_size); 
	print_disassemble(addr, code_size);
	
	return save_addr;
}

__attribute__((always_inline))
inline char* hex_to_string(unsigned char hex) 
{
	char str[5] = {0,};	
	sprintf(str, "\\x%x", hex);
	printf("hex to string %s\n", str);
	printf("hex to string %lx\n", &str);
	return str;
}


static void print_insn_detail(csh ud, cs_mode mode, cs_insn *ins)
{
	pr_dbg("PRINT INSTRUCTION DETAIL \n");
	int count, i, n;
	csh handle = ud;
	cs_x86 *x86;
        cs_detail *detail;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	detail = ins->detail;

	// print the groups this instruction belong to
	if (detail->groups_count > 0) {
		printf("\tThis instruction belongs to groups: ");
		for (n = 0; n < detail->groups_count; n++) {
			printf("%s ", cs_group_name(handle, detail->groups[n]));
		}
		printf("\n");
	}

	printf("\tinstruction size : %d\n", ins->size);
	printf("\tinstruction addr : 0x%x\n", ins->address);	
	print_string_hex("\tinstructions : ", (unsigned char *)ins->address, ins->size);
	x86 = &(ins->detail->x86);

	print_string_hex("\tPrefix:", x86->prefix, 4);
	print_string_hex("\tOpcode:", x86->opcode, 4);

	printf("\trex: 0x%x\n", x86->rex);
	printf("\taddr_size: %u\n", x86->addr_size);
	printf("\tmodrm: 0x%x\n", x86->modrm);
	printf("\tdisp: 0x%x\n", x86->disp);

	// SIB is not available in 16-bit mode
	if ((mode & CS_MODE_16) == 0) {
		printf("\tsib: 0x%x\n", x86->sib);
		if (x86->sib_base != X86_REG_INVALID)
			printf("\t\tsib_base: %s\n", cs_reg_name(handle, x86->sib_base));
		if (x86->sib_index != X86_REG_INVALID)
			printf("\t\tsib_index: %s\n", cs_reg_name(handle, x86->sib_index));
		if (x86->sib_scale != 0)
			printf("\t\tsib_scale: %d\n", x86->sib_scale);
	}

	// SSE code condition
	if (x86->sse_cc != X86_SSE_CC_INVALID) {
		printf("\tsse_cc: %u\n", x86->sse_cc);
	}

	// AVX code condition
	if (x86->avx_cc != X86_AVX_CC_INVALID) {
		printf("\tavx_cc: %u\n", x86->avx_cc);
	}

	// AVX Suppress All Exception
	if (x86->avx_sae) {
		printf("\tavx_sae: %u\n", x86->avx_sae);
	}

	// AVX Rounding Mode
	if (x86->avx_rm != X86_AVX_RM_INVALID) {
		printf("\tavx_rm: %u\n", x86->avx_rm);
	}

	count = cs_op_count(ud, ins, X86_OP_IMM);
	if (count) {
		printf("\timm_count: %u\n", count);
		for (i = 1; i < count + 1; i++) {
			int index = cs_op_index(ud, ins, X86_OP_IMM, i);
			printf("\t\timms[%u]: 0x%" PRIx64 "\n", i, x86->operands[index].imm);
		}
	}

	if (x86->op_count)
		printf("\top_count: %u\n", x86->op_count);
	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);

		switch((int)op->type) {
			case X86_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case X86_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case X86_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.segment != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.segment: REG = %s\n", i, cs_reg_name(handle, op->mem.segment));
				if (op->mem.base != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
				if (op->mem.scale != 1)
					printf("\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);
				break;
			default:
				break;
		}

		// AVX broadcast type
		if (op->avx_bcast != X86_AVX_BCAST_INVALID)
			printf("\t\toperands[%u].avx_bcast: %u\n", i, op->avx_bcast);

		// AVX zero opmask {z}
		if (op->avx_zero_opmask != false)
			printf("\t\toperands[%u].avx_zero_opmask: TRUE\n", i);

		printf("\t\toperands[%u].size: %u\n", i, op->size);
	}

	printf("\n");
}

#define CAN_USE_DYNAMIC 0x1
#define NOT_USE_DYNAMIC 0x2

// following function must be implemented in each architecture. 
int instruction_dynamicable(csh ud, cs_mode mode, cs_insn *ins)
{
	int count, i, n;
	csh handle = ud;
	cs_x86 *x86;
        cs_detail *detail;
	bool CALLnJMP = false;

	// default.  
	int status = NOT_USE_DYNAMIC;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return status;
	
	detail = ins->detail;

	// print the groups this instruction belong to
	if (detail->groups_count > 0) {
		pr_dbg2("\tThis instruction belongs to groups: ");
		for (n = 0; n < detail->groups_count; n++) {
			pr_dbg2("%s ", cs_group_name(handle, detail->groups[n]));
			if (detail->groups[n] == X86_GRP_CALL 
				|| detail->groups[n] == X86_GRP_JUMP) {
				pr_dbg2("%s ", cs_group_name(handle, detail->groups[n]));
				CALLnJMP = true;
			}
		}
		pr_dbg2("\n");
	}

	x86 = &(ins->detail->x86);

	if (!x86->op_count)
		return CAN_USE_DYNAMIC;
		
	pr_dbg2("0x%" PRIx64 "[%02d]:\t%s\t%s\n", ins->address, ins->size, ins->mnemonic, ins->op_str);
	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);

		switch((int)op->type) {
			case X86_OP_REG:
				status = CAN_USE_DYNAMIC;
				pr_dbg2("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case X86_OP_IMM:
				if (CALLnJMP) {	
					status = NOT_USE_DYNAMIC;
					return status;
				} else {
					status = CAN_USE_DYNAMIC;
				}
				pr_dbg2("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case X86_OP_MEM:
				// temporary till discover possibility of x86 instructions. 
				status = NOT_USE_DYNAMIC;
				pr_dbg2("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.segment != X86_REG_INVALID)
					pr_dbg2("\t\t\toperands[%u].mem.segment: REG = %s\n", i, cs_reg_name(handle, op->mem.segment));
				if (op->mem.base != X86_REG_INVALID)
					pr_dbg2("\t\t\toperands[%u].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					pr_dbg2("\t\t\toperands[%u].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
				if (op->mem.scale != 1)
					pr_dbg2("\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
				if (op->mem.disp != 0)
					pr_dbg2("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);
				return status;
			default:
				break;
		}
	}
	return status;
}


struct address_entry {
	uintptr_t addr;
	uintptr_t saved_addr;
	struct list_head list;
};

static LIST_HEAD(address_list);


// live code patch a.k.a instrumentation. 
int do_dynamic_instrument(uintptr_t address, uint32_t insn_size) 
{
	pr_dbg("Do dynamic instrument\n");
	struct address_entry* el;
	puchar saved_code;
	saved_code = patch_code(address, &g_call_insn, insn_size);
	if (saved_code) {
		// TODO : keep and manage saved_code chunks.
		pr_dbg("Keep original instruction [%03d]: %llx\n", insn_size, (uintptr_t)saved_code);
		el = malloc(sizeof(struct address_entry));
		el->addr = address;
		el->saved_addr = saved_code;
		
		list_add_tail(&el->list, &address_list); 

	} else {
		// TODO : error handling
		pr_err("GRRRRRRRRRRRRRRRRRRRRR......\n");
	}
}

#define INSTRUMENT_ERR_INSTRUCTION		0x0001
#define INSTRUMENT_ERR_OTHERWISE		0x0002
#define INSTRUMENT_SUCCESS			0x0000

int dynamic_instrument(uintptr_t address, uint32_t size) 
{
	pr_dbg("read memory at %lx amount : %d \n", address, size);

	cs_insn *insn;
	int code_size = 0;
	int count = cs_disasm(csh_handle, (unsigned char*)address, size, address, 0, &insn);
	pr_dbg2("DISASM:\n");
	int j;
	for(j = 0;j < count;j++) {
		pr_dbg2("0x%" PRIx64 "[%02d]: %s  %s\n", insn[j].address, insn[j].size, insn[j].mnemonic, insn[j].op_str);
		int dynamicable = instruction_dynamicable(csh_handle, CS_MODE_64, &insn[j]);
		if (dynamicable & NOT_USE_DYNAMIC) { 
			pr_dbg("%d\n", dynamicable);
			pr_dbg("The instruction not supported : %s\t %s\n", insn[j].mnemonic, insn[j].op_str);
			return INSTRUMENT_ERR_INSTRUCTION; 
		}

		code_size += insn[j].size;
		if (code_size > instruction_size -1) {
			break;
		} 
	}
	
	do_dynamic_instrument(address, code_size);	
	cs_free(insn, count);	
	return INSTRUMENT_SUCCESS; 
}

void read_memory(uintptr_t address, uint32_t size) 
{
	pr_dbg("read memory at %lx amount : %d \n", address, size);

	cs_insn *insn;
	int code_size = 0;
	int count = cs_disasm(csh_handle, (unsigned char*)address, size, address, 0, &insn);
	pr_dbg2("DISASM:\n");
	int j;
	for(j = 0;j < count;j++) {
		code_size += insn[j].size;
		pr_dbg2("0x%" PRIx64 ": %s  %s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
		pr_dbg2("0x%" PRIx64 ": %d \n", insn[j].address, insn[j].size);
		print_insn_detail(csh_handle, CS_MODE_64, &insn[j]);
		int dynamicable = instruction_dynamicable(csh_handle, CS_MODE_64, &insn[j]);
		if (dynamicable && NOT_USE_DYNAMIC) return -1; 

		if (code_size > 7) {
			break;
		} 
	}
	cs_free(insn, count);	
}

int disassembler_init() 
{
	// TODO : we have to determined architecture and mode when compile.
	if(cs_open(CS_ARCH_X86, CS_MODE_64, &csh_handle) != CS_ERR_OK) {
		pr_dbg("CANNOT OPEN CAPSTONE\n");
		return -1;
	}
	cs_option(csh_handle, CS_OPT_DETAIL, CS_OPT_ON);
	pr_dbg("CREATE CAPSTONE SUCCESS\n");	
	return 0;
}

void disassemble(uintptr_t address, uint32_t size) 
{
	// read_memory(address, size);
	dynamic_instrument(address, size);
	struct address_entry* entry;
	
	pr_dbg("=================================\n");
	list_for_each_entry(entry, &address_list, list) {
		pr_dbg("%lx %lx\n", entry->addr, entry->saved_addr);
	}
}

/* time filter in nsec */
uint64_t mcount_threshold;

/* symbol table of main executable */
extern struct symtabs symtabs;

/* size of shmem buffer to save uftrace_record */
extern int shmem_bufsize;

/* global flag to control mcount behavior */
extern unsigned long mcount_global_flags;

/* TSD key to save mtd below */
extern pthread_key_t mtd_key;

/* thread local data to trace function execution */
extern TLS struct mcount_thread_data mtd;

/* pipe file descriptor to communite to uftrace */
extern int pfd;

/* maximum depth of mcount rstack */
static int mcount_rstack_max = MCOUNT_RSTACK_MAX;

/* name of main executable */
char *mcount_exename;

/* whether it should update pid filter manually */
bool kernel_pid_update;

/* system page size */
int page_size_in_kb;

/* call depth to filter */
static int __maybe_unused mcount_depth = MCOUNT_DEFAULT_DEPTH;

/* boolean flag to turn on/off recording */
static bool __maybe_unused mcount_enabled = true;

/* function filtering mode - inclusive or exclusive */
static enum filter_mode __maybe_unused mcount_filter_mode = FILTER_MODE_NONE;

/* tree of trigger actions */
static struct rb_root __maybe_unused mcount_triggers = RB_ROOT;

/* save the breakpoint address had restored recently */
static uintptr_t restored_bp; 

void handle_signal(int signal, siginfo_t *siginfo, void *uc0) 
{
	const char *signal_name;
	sigset_t pending;
	struct timeval val;

	struct ucontext *uc;
	struct sigcontext *sc;
	uint64_t rip;
	int i;

	// Find out which signal we're handling
	switch (signal) {
		case SIGHUP:
			signal_name = "SIGHUP";
			break;
		case SIGUSR1:
			signal_name = "SIGUSR1";
			break;
		case SIGINT:
			printf("Caught SIGINT, exiting now\n");
			exit(0);
		case SIGTRAP:
			gettimeofday(&val, NULL);
			printf("%ld:%ld\n", val.tv_sec, val.tv_usec);
			printf("CATCH SIGTRAP\n");
			uc = (struct ucontext *)uc0;
			sc = &uc->uc_mcontext;
			rip = sc->rip -1;
			restored_bp = rip;
			sc->rip -= 1;
			uintptr_t* rsp = (uintptr_t *)sc->rsp;
			uintptr_t* rbp = (uintptr_t *)sc->rbp;
			for(i=0;i<10;i++) {
				printf("ST[%lx] %lx\n", rsp + i, rsp[i]);
			}
			printf("CHILD : %lx\n", rsp[0]);	
			printf("PARENT : %lx\n",rbp[1]);	
			// __fentry__();
			//mcount_entry(&rbp[1], rsp[0], 0);
			mcount_entry(&rsp[0], rip, 0);
			printf("SIG RIP : %lx\n", sc->rip);
			printf("RBP : %lx\n", rbp);
			printf("caller RET addr : %lx\n", rbp+1);
			printf("caller RET valv : %lx\n", *((uintptr_t *)(rbp+1)));

			//(uintptr_t *)rbp-1 = fentry_return;
			//*((uintptr_t *)rbp-1) = fentry_return;

			// rsp[0] = fentry_return;
			// printf("Change caller RET %lx to fentry_return : %lx\n", &rsp[0], rsp[0]); 

			//*((uintptr_t *)(rbp+1)) = fentry_return;
			//printf("Change caller RET to fentry_return : %lx\n", *((uintptr_t *)(rbp+1))); 
			//remove_break_point(sc->rip);
			for(i=0;i<10;i++) {
				printf("ST[%lx] %lx\n", rsp + i, rsp[i]);
			}

			break;
		default:
			fprintf(stderr, "Caught wrong signal: %d\n", signal);
			return;
	}
}

void set_signal_handler() 
{
	printf("SIGNAL HANDLER REGISTER\n");
	struct sigaction sa;

	// Print pid, so that we can send signals from other shells
	printf("My pid is: %d\n", getpid());

	// Setup the sighub handler
	sa.sa_handler = &handle_signal;

	// Restart the system call, if at all possible
	sa.sa_flags = SA_SIGINFO;

	// Block every signal during the handler
	sigfillset(&sa.sa_mask);

	// Intercept SIGHUP and SIGINT
	if (sigaction(SIGHUP, &sa, NULL) == -1) {
		perror("Error: cannot handle SIGHUP"); // Should not happen
	}

	if (sigaction(SIGTRAP, &sa, NULL) == -1) {
		perror("Error: cannot handle SIGTRAP"); // Should not happen
	}

	if (sigaction(SIGUSR1, &sa, NULL) == -1) {
		perror("Error: cannot handle SIGUSR1"); // Should not happen
	}

	// Will always fail, SIGKILL is intended to force kill your process
	if (sigaction(SIGKILL, &sa, NULL) == -1) {
		perror("Cannot handle SIGKILL"); // Will always happen
		printf("You can never handle SIGKILL anyway...\n");
	}

	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("Error: cannot handle SIGINT"); // Should not happen
	}
	printf("SIGNAL HANDLER DONE\n");
}

static struct sigaction old_sigact[2];

static const struct {
	int code;
	char *msg;
} sigsegv_codes[] = {
	{ SEGV_MAPERR, "address not mapped" },
	{ SEGV_ACCERR, "invalid permission" },
#ifdef SEGV_BNDERR
	{ SEGV_BNDERR, "bound check failed" },
#endif
#ifdef SEGV_PKUERR
	{ SEGV_PKUERR, "protection key check failed" },
#endif
};

static void segv_handler(int sig, siginfo_t *si, void *ctx)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	int idx;

	/* set line buffer mode not to discard crash message */
	setlinebuf(outfp);

	for (idx = 0; idx < (int)ARRAY_SIZE(sigsegv_codes); idx++) {
		if (sig != SIGSEGV)
			break;

		if (si->si_code == sigsegv_codes[idx].code) {
			pr_red("Segmentation fault: %s (addr: %p)\n",
			       sigsegv_codes[idx].msg, si->si_addr);
			break;
		}
	}
	if (sig != SIGSEGV || idx == (int)ARRAY_SIZE(sigsegv_codes)) {
		pr_red("process crashed by signal %d: %s (si_code: %d)\n",
		       sig, strsignal(sig), si->si_code);
	}

	mtdp = get_thread_data();
	if (check_thread_data(mtdp))
		goto out;

	mcount_rstack_restore(mtdp);

	idx = mtdp->idx - 1;
	/* flush current rstack on crash */
	rstack = &mtdp->rstack[idx];
	record_trace_data(mtdp, rstack, NULL);

	if (dbg_domain[PR_DOMAIN]) {
		pr_red("Backtrace from uftrace:\n");
		pr_red("=====================================\n");

		while (rstack >= mtdp->rstack) {
			struct sym *parent, *child;
			char *pname, *cname;

			parent = find_symtabs(&symtabs, rstack->parent_ip);
			pname = symbol_getname(parent, rstack->parent_ip);
			child  = find_symtabs(&symtabs, rstack->child_ip);
			cname = symbol_getname(child, rstack->child_ip);

			pr_red("[%d] (%s[%lx] <= %s[%lx])\n", idx--,
			       cname, rstack->child_ip, pname, rstack->parent_ip);

			symbol_putname(parent, pname);
			symbol_putname(child, cname);

			rstack--;
		}
	}

out:
	sigaction(sig, &old_sigact[(sig == SIGSEGV)], NULL);
	raise(sig);
}

uintptr_t find_origin_code_addr(uintptr_t addr)
{
	uintptr_t patched_addr, ret_addr = NULL;
	patched_addr = addr - instruction_size;
	struct address_entry* entry;	
	list_for_each_entry(entry, &address_list, list) {

		if (entry->addr == patched_addr) {
			pr_dbg("found patched address : %lx\n", entry->addr);
			ret_addr = entry->saved_addr;
			break;
		}
	}
	pr_dbg("Address : %lx %lx\n", entry->addr, entry->saved_addr);

	return ret_addr;
}

int dynamic_entry(unsigned long *parent_loc, unsigned long child, 
		 struct mcount_regs *regs)
{
	pr_dbg("dynamic_entry %lx, %lx, %lx\n", parent_loc, child, regs);
	int result;
	result = mcount_entry(parent_loc, child, regs);
	if (!result) {
		/*
		   dynamic_entry returns the address
		   holding the patched original code.
		 */
		uintptr_t origin_code_addr = find_origin_code_addr(child);
		return origin_code_addr;
	} else {
		// at here, 0 mean there is no patched. 
		return 0;
	}
}

static void setup_environ_from_file() {
	int fd;
	char buf[1024] = {0,};
	bool keyflag = false;
	char* key, *value;

	fd = open("/tmp/uftrace_environ_file", O_RDONLY);
	
	if (fd < 0) return -1;

	read(fd, buf, 1024);
	close(fd);

	char* token = strtok(buf, "=\n");
	keyflag = true;
	do {
		if (!keyflag) {
			value = token;
			pr_dbg2("value %s\n", token);
			pr_dbg2("value %s\n", value);
			setenv(key, value, 1);
			pr_dbg2("setenv done\n");
			keyflag = true;
		} else {
			key = token;
			pr_dbg2("key %s\n", key);
			keyflag = false;
		}
	} while(token = strtok(NULL, "=\n"));
}

void test_bp()
{
	pr_dbg("TEST BP\n");
	char *dirname;
	int target_pid = getpid();
	dirname = getenv("UFTRACE_DIR");
	if (dirname == NULL)
		dirname = UFTRACE_DIR_NAME;

	symtabs.dirname = dirname;
	mcount_exename = read_exename();
	record_proc_maps(dirname, mcount_session_name(), &symtabs);
	set_kernel_base(&symtabs, mcount_session_name());
	load_symtabs(&symtabs, NULL, mcount_exename);

	struct timeval val;
	gettimeofday(&val, NULL);
	pr_dbg2("%ld:%ld\n", val.tv_sec, val.tv_usec);

	struct uftrace_mmap *map, *curr;
	map = symtabs.maps;
	pr_dbg("CHECK MMAP \n");
	while (map) {
		curr = map;
		map = map->next;
		// check 	
		if (curr->prot[2] == 'x') {
			uint64_t size = curr->end - curr->start;
			pr_dbg("0x%lx - 0x%lx\n", curr->start, curr->end);
			pr_dbg("SIZE : 0x%lx\n", size);
			SETRWX(curr->start, size); 
		}
	}
	struct symtab uftrace_symtab = symtabs.symtab;
	// attach to target. pray all child thread have to work correctly.

	pr_dbg("TARGET PID : %d\n", target_pid);
	// debugger_init(target_pid);
	mprotect(0x400000, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);
	int base_addr = 0x000000;
	int index;

	disassembler_init();
	for(index=0;index < uftrace_symtab.nr_sym;index++) {
		struct sym _sym = uftrace_symtab.sym[index];
		pr_dbg("[%d] %lx  %d :  %s\n", index, base_addr + _sym.addr, _sym.size, _sym.name);
	
		// exclude function.	
		if (!strncmp(_sym.name, "_start", 6)) {
			continue;
		}
		
		// at least, function need to bigger then call instruction. 
		// TODO : conform with feature.
		if (_sym.size > sizeof(g_call_insn)) {
			// set break point and save origin instruction. 
			// set_break_point(base_addr + _sym.addr);
			disassemble(_sym.addr, _sym.size);
		}
	}

	gettimeofday(&val, NULL);
	pr_dbg2("%ld:%ld\n", val.tv_sec, val.tv_usec);
	pr_dbg("PLTHOOK : %lx\n", plthook_resolver_addr);
	pr_dbg("PLTHOOK : %lx\n", pltgot_addr);
	pr_dbg("Continue");
}


#ifndef UNIT_TEST

void pre_startup()
{
	setup_environ_from_file();
}

void config_for_dynamic() {
	char *pipefd_str;
	char *uftrace_pid_str;
	int uftrace_pid;

	struct stat statbuf;

	uftrace_pid_str = getenv("UFTRACE_PID");
	if (uftrace_pid_str) {
		pr_dbg("uftrace process PID : %s\n", uftrace_pid_str);
		uftrace_pid = strtol(uftrace_pid_str, NULL, 0);
		if (uftrace_pid == NULL) {
			pr_err_ns("ERROR");
		}
	} else {
		pr_dbg("uftrace process PID : %s\n", uftrace_pid_str);
		pr_err_ns("ERROR");
	} 	
	if (pipefd_str) {
		pfd = strtol(pipefd_str, NULL, 0);

		char fd_path[64];
		snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", uftrace_pid, pfd);
		pr_dbg("open uftrace process : %s\n", fd_path);
		pfd = open(fd_path, O_RDWR);
		/* minimal sanity check */
		if (fstat(pfd, &statbuf) < 0 || !S_ISFIFO(statbuf.st_mode)) {
			pr_dbg("ignore invalid pipe fd: %d\n", pfd);
			pfd = -1;
		}
	}
}

void post_startup()
{
	config_for_dynamic();		
	test_bp();	
}

#else  /* UNIT_TEST */



#endif /* UNIT_TEST */
