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
	printf("DISASM:\n");
	int j;
	for(j = 0;j < count;j++) {
		printf("0x%"PRIx64"[%02d]:%s %s\n", insn[j].address, insn[j].size, insn[j].mnemonic, insn[j].op_str);
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

	// make instruction to patch. 	
	for(int i=0;i < 4;i++) {
		printf("%02x\n", *(ptr+i));
		call_insn[2 + i] = *(ptr+i); // FF 15 XX XX XX XX 
	}
	print_string_hex("INSTRUMENT INSTRUCTION : ", call_insn, instruction_size);

	uintptr_t alloc_addr = malloc(saved_code_size);	
	memset(alloc_addr, NULL, saved_code_size); 
	SETRWX(alloc_addr, saved_code_size);

	save_addr = (puchar)alloc_addr;
	code_addr = (puchar)addr;

	// patch the code!!
	for(int i=0;i < code_size;i++) {
		save_addr[i] = code_addr[i];
		if (i > instruction_size-1) {
			printf("patching... : %x to %x \n", code_addr[i], 0x90);
			code_addr[i] = 0x90; 
		} else {
			printf("patching... : %x to %x \n", code_addr[i], call_insn[i]);
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
	printf("RETURN ADDRESS : %llx\n", &code_addr[code_size]);
	
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
	int count, i;
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
		for (int n = 0; n < detail->groups_count; n++) {
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
	int count, i;
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
		for (int n = 0; n < detail->groups_count; n++) {
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
		pr_dbg("Keep original instruction : %llx\n", (uintptr_t)saved_code);
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
	printf("DISASM:\n");
	int j;
	for(j = 0;j < count;j++) {
		printf("0x%" PRIx64 "[%02d]: %s  %s\n", insn[j].address, insn[j].size, insn[j].mnemonic, insn[j].op_str);
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
	printf("DISASM:\n");
	int j;
	for(j = 0;j < count;j++) {
		code_size += insn[j].size;
		printf("0x%" PRIx64 ": %s  %s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
		printf("0x%" PRIx64 ": %d \n", insn[j].address, insn[j].size);
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
	
	printf("=================================\n");
	list_for_each_entry(entry, &address_list, list) {
		printf("%lx %lx\n", entry->addr, entry->saved_addr);
	}
}

/* time filter in nsec */
uint64_t mcount_threshold;

/* symbol table of main executable */
struct symtabs symtabs = {
	.flags = SYMTAB_FL_DEMANGLE | SYMTAB_FL_ADJ_OFFSET,
};

/* size of shmem buffer to save uftrace_record */
int shmem_bufsize = SHMEM_BUFFER_SIZE;

/* global flag to control mcount behavior */
unsigned long mcount_global_flags = MCOUNT_GFL_SETUP;

/* TSD key to save mtd below */
pthread_key_t mtd_key = (pthread_key_t)-1;

/* thread local data to trace function execution */
TLS struct mcount_thread_data mtd;

/* pipe file descriptor to communite to uftrace */
int pfd = -1;

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
			for(int i=0;i<10;i++) {
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
			remove_break_point(sc->rip);
			for(int i=0;i<10;i++) {
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

#ifndef DISABLE_MCOUNT_FILTER
static void mcount_filter_init(void)
{
	char *filter_str    = getenv("UFTRACE_FILTER");
	char *trigger_str   = getenv("UFTRACE_TRIGGER");
	char *argument_str  = getenv("UFTRACE_ARGUMENT");
	char *retval_str    = getenv("UFTRACE_RETVAL");
	char *autoargs_str  = getenv("UFTRACE_AUTO_ARGS");

	load_module_symtabs(&symtabs);

	/* setup auto-args only if argument/return value is used */
	if (argument_str || retval_str || autoargs_str ||
	    (trigger_str && (strstr(trigger_str, "arg") ||
			     strstr(trigger_str, "retval"))))
		setup_auto_args();

	uftrace_setup_filter(filter_str, &symtabs, &mcount_triggers,
			     &mcount_filter_mode, false);
	uftrace_setup_trigger(trigger_str, &symtabs, &mcount_triggers,
			      &mcount_filter_mode, false);
	uftrace_setup_argument(argument_str, &symtabs, &mcount_triggers, false);
	uftrace_setup_retval(retval_str, &symtabs, &mcount_triggers, false);

	if (autoargs_str) {
		uftrace_setup_argument(get_auto_argspec_str(), &symtabs,
				       &mcount_triggers, true);
		uftrace_setup_retval(get_auto_retspec_str(), &symtabs,
				     &mcount_triggers, true);
	}

	if (getenv("UFTRACE_DEPTH"))
		mcount_depth = strtol(getenv("UFTRACE_DEPTH"), NULL, 0);

	if (getenv("UFTRACE_DISABLED"))
		mcount_enabled = false;
}

static void mcount_filter_setup(struct mcount_thread_data *mtdp)
{
	mtdp->filter.depth  = mcount_depth;
	mtdp->filter.time   = mcount_threshold;
	mtdp->enable_cached = mcount_enabled;
	mtdp->argbuf        = xmalloc(mcount_rstack_max * ARGBUF_SIZE);
}

static void mcount_filter_release(struct mcount_thread_data *mtdp)
{
	free(mtdp->argbuf);
	mtdp->argbuf = NULL;
}
#endif /* DISABLE_MCOUNT_FILTER */

static void send_session_msg(struct mcount_thread_data *mtdp, const char *sess_id)
{
	struct uftrace_msg_sess sess = {
		.task = {
			.time = mcount_gettime(),
			.pid = getpid(),
			.tid = mcount_gettid(mtdp),
		},
		.namelen = strlen(mcount_exename),
	};
	struct uftrace_msg msg = {
		.magic = UFTRACE_MSG_MAGIC,
		.type = UFTRACE_MSG_SESSION,
		.len = sizeof(sess) + sess.namelen,
	};
	struct iovec iov[3] = {
		{ .iov_base = &msg, .iov_len = sizeof(msg), },
		{ .iov_base = &sess, .iov_len = sizeof(sess), },
		{ .iov_base = mcount_exename, .iov_len = sess.namelen, },
	};
	int len = sizeof(msg) + msg.len;

	if (pfd < 0)
		return;

	mcount_memcpy4(sess.sid, sess_id, sizeof(sess.sid));

	if (writev(pfd, iov, 3) != len) {
		if (!mcount_should_stop())
			pr_err("write tid info failed");
	}
}

/* to be used by pthread_create_key() */
static void mtd_dtor(void *arg)
{
	struct mcount_thread_data *mtdp = arg;
	struct uftrace_msg_task tmsg;

	/* this thread is done, do not enter anymore */
	mtdp->recursion_guard = true;

	free(mtdp->rstack);
	mtdp->rstack = NULL;

	mcount_filter_release(mtdp);
	shmem_finish(mtdp);

	tmsg.pid = getpid(),
	tmsg.tid = mcount_gettid(mtdp),
	tmsg.time = mcount_gettime();

	/* dtor for script support */
	if (SCRIPT_ENABLED && script_str)
		script_uftrace_end();

	uftrace_send_message(UFTRACE_MSG_TASK_END, &tmsg, sizeof(tmsg));
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

static void mcount_init_file(void)
{
	pr_dbg("MOUNT INIT\n");
	struct sigaction sa = {
		.sa_sigaction = segv_handler,
		.sa_flags = SA_SIGINFO,
	};

	send_session_msg(&mtd, mcount_session_name());
	pr_dbg("new session started: %.*s: %s\n",
	       SESSION_ID_LEN, mcount_session_name(), basename(mcount_exename));

	sigemptyset(&sa.sa_mask);
	sigaction(SIGABRT, &sa, &old_sigact[0]);
	sigaction(SIGSEGV, &sa, &old_sigact[1]);
}

struct mcount_thread_data * mcount_prepare(void)
{
	pr_dbg("mcount_thread_data\n");
	static pthread_once_t once_control = PTHREAD_ONCE_INIT;
	struct mcount_thread_data *mtdp = &mtd;
	struct uftrace_msg_task tmsg;

	/*
	 * If an executable implements its own malloc(),
	 * following recursion could occur
	 *
	 * mcount_entry -> mcount_prepare -> xmalloc -> mcount_entry -> ...
	 */
	if (mtdp->recursion_guard)
		return NULL;

	mtdp->recursion_guard = true;
	compiler_barrier();

	mcount_filter_setup(mtdp);
	mtdp->rstack = xmalloc(mcount_rstack_max * sizeof(*mtd.rstack));

	pthread_once(&once_control, mcount_init_file);
	prepare_shmem_buffer(mtdp);

	pthread_setspecific(mtd_key, mtdp);

	/* time should be get after session message sent */
	tmsg.pid = getpid(),
	tmsg.tid = mcount_gettid(mtdp),
	tmsg.time = mcount_gettime();

	uftrace_send_message(UFTRACE_MSG_TASK_START, &tmsg, sizeof(tmsg));

	update_kernel_tid(tmsg.tid);

	return mtdp;
}

static void mcount_finish(void)
{
	if (mcount_global_flags & MCOUNT_GFL_FINISH)
		return;

	mcount_global_flags |= MCOUNT_GFL_FINISH;
	mtd_dtor(&mtd);

	__sync_synchronize();

	pthread_key_delete(mtd_key);
	if (pfd != -1) {
		close(pfd);
		pfd = -1;
	}

	finish_auto_args();
}

static bool mcount_check_rstack(struct mcount_thread_data *mtdp)
{
	if (mtdp->idx >= mcount_rstack_max) {
		static bool warned = false;

		if (!warned) {
			pr_warn("too deeply nested calls: %d\n", mtdp->idx);
			warned = true;
		}
		return true;
	}
	return false;
}

#ifndef DISABLE_MCOUNT_FILTER
extern void * get_argbuf(struct mcount_thread_data *, struct mcount_ret_stack *);

/* update filter state from trigger result */
enum filter_result mcount_entry_filter_check(struct mcount_thread_data *mtdp,
					     unsigned long child,
					     struct uftrace_trigger *tr)
{
	pr_dbg3("<%d> enter %lx\n", mtdp->idx, child);

	if (mcount_check_rstack(mtdp))
		return FILTER_RSTACK;

	/* save original depth and time to restore at exit time */
	mtdp->filter.saved_depth = mtdp->filter.depth;
	mtdp->filter.saved_time  = mtdp->filter.time;

	/* already filtered by notrace option */
	if (mtdp->filter.out_count > 0)
		return FILTER_OUT;

	uftrace_match_filter(child, &mcount_triggers, tr);

	pr_dbg3(" tr->flags: %lx, filter mode, count: [%d] %d/%d\n",
		tr->flags, mcount_filter_mode, mtdp->filter.in_count,
		mtdp->filter.out_count);

	if (tr->flags & TRIGGER_FL_FILTER) {
		if (tr->fmode == FILTER_MODE_IN)
			mtdp->filter.in_count++;
		else if (tr->fmode == FILTER_MODE_OUT)
			mtdp->filter.out_count++;

		/* apply default filter depth when match */
		mtdp->filter.depth = mcount_depth;
	}
	else {
		/* not matched by filter */
		if (mcount_filter_mode == FILTER_MODE_IN &&
		    mtdp->filter.in_count == 0)
			return FILTER_OUT;
	}

#define FLAGS_TO_CHECK  (TRIGGER_FL_DEPTH | TRIGGER_FL_TRACE_ON |	\
			 TRIGGER_FL_TRACE_OFF | TRIGGER_FL_TIME_FILTER)

	if (tr->flags & FLAGS_TO_CHECK) {
		if (tr->flags & TRIGGER_FL_DEPTH)
			mtdp->filter.depth = tr->depth;

		if (tr->flags & TRIGGER_FL_TRACE_ON)
			mcount_enabled = true;

		if (tr->flags & TRIGGER_FL_TRACE_OFF)
			mcount_enabled = false;

		if (tr->flags & TRIGGER_FL_TIME_FILTER)
			mtdp->filter.time = tr->time;
	}

#undef FLAGS_TO_CHECK

	if (mtdp->filter.depth <= 0)
		return FILTER_OUT;

	mtdp->filter.depth--;
	return FILTER_IN;
}

/* save current filter state to rstack */
void mcount_entry_filter_record(struct mcount_thread_data *mtdp,
				struct mcount_ret_stack *rstack,
				struct uftrace_trigger *tr,
				struct mcount_regs *regs)
{
	if (mtdp->filter.out_count > 0 ||
	    (mtdp->filter.in_count == 0 && mcount_filter_mode == FILTER_MODE_IN))
		rstack->flags |= MCOUNT_FL_NORECORD;

	rstack->filter_depth = mtdp->filter.saved_depth;
	rstack->filter_time  = mtdp->filter.saved_time;

#define FLAGS_TO_CHECK  (TRIGGER_FL_FILTER | TRIGGER_FL_RETVAL |	\
			 TRIGGER_FL_TRACE | TRIGGER_FL_FINISH)

	if (tr->flags & FLAGS_TO_CHECK) {
		if (tr->flags & TRIGGER_FL_FILTER) {
			if (tr->fmode == FILTER_MODE_IN)
				rstack->flags |= MCOUNT_FL_FILTERED;
			else
				rstack->flags |= MCOUNT_FL_NOTRACE;
		}

		/* check if it has to keep arg_spec for retval */
		if (tr->flags & TRIGGER_FL_RETVAL) {
			rstack->pargs = tr->pargs;
			rstack->flags |= MCOUNT_FL_RETVAL;
		}

		if (tr->flags & TRIGGER_FL_TRACE)
			rstack->flags |= MCOUNT_FL_TRACE;

		if (tr->flags & TRIGGER_FL_FINISH) {
			record_trace_data(mtdp, rstack, NULL);
			uftrace_send_message(UFTRACE_MSG_FINISH, NULL, 0);
			mcount_finish();
			return;
		}
	}

#undef FLAGS_TO_CHECK

	if (!(rstack->flags & MCOUNT_FL_NORECORD)) {
		mtdp->record_idx++;

		if (!mcount_enabled) {
			rstack->flags |= MCOUNT_FL_DISABLED;
			/*
			 * Flush existing rstack when mcount_enabled is off
			 * (i.e. disabled).  Note that changing to enabled is
			 * already handled in record_trace_data() on exit path
			 * using the MCOUNT_FL_DISALBED flag.
			 */
			if (unlikely(mtdp->enable_cached))
				record_trace_data(mtdp, rstack, NULL);
		}
		else {
			if (tr->flags & TRIGGER_FL_ARGUMENT)
				save_argument(mtdp, rstack, tr->pargs, regs);
			if (tr->flags & TRIGGER_FL_READ)
				save_trigger_read(mtdp, rstack, tr->read);

			if (mtdp->nr_events) {
				bool flush = false;
				int i;

				/*
				 * Flush rstacks if async event was recorded
				 * as it only has limited space for the events.
				 */
				for (i = 0; i < mtdp->nr_events; i++)
					if (mtdp->event[i].idx == ASYNC_IDX)
						flush = true;

				if (flush)
					record_trace_data(mtdp, rstack, NULL);
			}
		}

		/* script hooking for function entry */
		if (SCRIPT_ENABLED && script_str) {
			unsigned long entry_addr = rstack->child_ip;
			struct sym *sym = find_symtabs(&symtabs, entry_addr);
			char *symname = symbol_getname(sym, entry_addr);
			struct script_context sc_ctx;

			if (!script_match_filter(symname))
				goto skip;

			sc_ctx.tid       = mcount_gettid(mtdp);
			sc_ctx.depth     = rstack->depth;
			sc_ctx.timestamp = rstack->start_time;
			sc_ctx.address   = entry_addr;
			sc_ctx.name      = symname;

			if (tr->flags & TRIGGER_FL_ARGUMENT) {
				unsigned *argbuf = get_argbuf(mtdp, rstack);

				sc_ctx.arglen  = argbuf[0];
				sc_ctx.argbuf  = &argbuf[1];
				sc_ctx.argspec = tr->pargs;
			}
			else {
				/* prevent access to arguments */
				sc_ctx.arglen  = 0;
			}

			/* accessing argument in script might change arch-context */
			mcount_save_arch_context(&mtdp->arch);
			script_uftrace_entry(&sc_ctx);
			mcount_restore_arch_context(&mtdp->arch);

skip:
			symbol_putname(sym, symname);
		}

#define FLAGS_TO_CHECK  (TRIGGER_FL_RECOVER | TRIGGER_FL_TRACE_ON | TRIGGER_FL_TRACE_OFF)

		if (tr->flags & FLAGS_TO_CHECK) {
			if (tr->flags & TRIGGER_FL_RECOVER) {
				mcount_rstack_restore(mtdp);
				*rstack->parent_loc = (unsigned long) mcount_return;
				rstack->flags |= MCOUNT_FL_RECOVER;
			}
			if (tr->flags & (TRIGGER_FL_TRACE_ON | TRIGGER_FL_TRACE_OFF))
				mtdp->enable_cached = mcount_enabled;
		}
	}

#undef FLAGS_TO_CHECK

}

/* restore filter state from rstack */
void mcount_exit_filter_record(struct mcount_thread_data *mtdp,
			       struct mcount_ret_stack *rstack,
			       long *retval)
{
	uint64_t time_filter = mtdp->filter.time;

	pr_dbg3("<%d> exit  %lx\n", mtdp->idx, rstack->child_ip);

#define FLAGS_TO_CHECK  (MCOUNT_FL_FILTERED | MCOUNT_FL_NOTRACE | MCOUNT_FL_RECOVER)

	if (rstack->flags & FLAGS_TO_CHECK) {
		if (rstack->flags & MCOUNT_FL_FILTERED)
			mtdp->filter.in_count--;
		else if (rstack->flags & MCOUNT_FL_NOTRACE)
			mtdp->filter.out_count--;

		if (rstack->flags & MCOUNT_FL_RECOVER)
			mcount_rstack_reset(mtdp);
	}

#undef FLAGS_TO_CHECK

	mtdp->filter.depth = rstack->filter_depth;
	mtdp->filter.time  = rstack->filter_time;

	if (!(rstack->flags & MCOUNT_FL_NORECORD)) {
		if (mtdp->record_idx > 0)
			mtdp->record_idx--;

		if (!mcount_enabled)
			return;

		if (!(rstack->flags & MCOUNT_FL_RETVAL))
			retval = NULL;

		if (rstack->end_time - rstack->start_time > time_filter ||
		    rstack->flags & (MCOUNT_FL_WRITTEN | MCOUNT_FL_TRACE)) {
			if (record_trace_data(mtdp, rstack, retval) < 0)
				pr_err("error during record");
		}
		else if (mtdp->nr_events) {
			bool flush = false;
			int i, k;

			/*
			 * Record rstacks if async event was recorded
			 * in the middle of the function.  Otherwise
			 * update event count to drop filtered ones.
			 */
			for (i = 0, k = 0; i < mtdp->nr_events; i++) {
				if (mtdp->event[i].idx == ASYNC_IDX)
					flush = true;
				if (mtdp->event[i].idx < mtdp->idx)
					k = i + 1;
			}

			if (flush)
				record_trace_data(mtdp, rstack, retval);
			else
				mtdp->nr_events = k;  /* invalidate sync events */
		}

		/* script hooking for function exit */
		if (SCRIPT_ENABLED && script_str) {
			unsigned long entry_addr = rstack->child_ip;
			struct sym *sym = find_symtabs(&symtabs, entry_addr);
			char *symname = symbol_getname(sym, entry_addr);
			struct script_context sc_ctx;

			if (!script_match_filter(symname))
				goto skip;

			sc_ctx.tid       = mcount_gettid(mtdp);
			sc_ctx.depth     = rstack->depth;
			sc_ctx.timestamp = rstack->start_time;
			sc_ctx.duration  = rstack->end_time - rstack->start_time;
			sc_ctx.address   = entry_addr;
			sc_ctx.name      = symname;

			if (rstack->flags & MCOUNT_FL_RETVAL) {
				unsigned *argbuf = get_argbuf(mtdp, rstack);

				sc_ctx.arglen  = argbuf[0];
				sc_ctx.argbuf  = &argbuf[1];
				sc_ctx.argspec = rstack->pargs;
			}
			else {
				/* prevent access to retval*/
				sc_ctx.arglen  = 0;
			}

			/* accessing argument in script might change arch-context */
			mcount_save_arch_context(&mtdp->arch);
			script_uftrace_exit(&sc_ctx);
			mcount_restore_arch_context(&mtdp->arch);

skip:
			symbol_putname(sym, symname);
		}
	}
}

#else /* DISABLE_MCOUNT_FILTER */
enum filter_result mcount_entry_filter_check(struct mcount_thread_data *mtdp,
					     unsigned long child,
					     struct uftrace_trigger *tr)
{
	if (mcount_check_rstack(mtdp))
		return FILTER_RSTACK;

	return FILTER_IN;
}

void mcount_entry_filter_record(struct mcount_thread_data *mtdp,
				struct mcount_ret_stack *rstack,
				struct uftrace_trigger *tr,
				struct mcount_regs *regs)
{
	mtdp->record_idx++;
}

void mcount_exit_filter_record(struct mcount_thread_data *mtdp,
			       struct mcount_ret_stack *rstack,
			       long *retval)
{
	mtdp->record_idx--;

	if (rstack->end_time - rstack->start_time > mcount_threshold ||
	    rstack->flags & MCOUNT_FL_WRITTEN) {
		if (record_trace_data(mtdp, rstack, NULL) < 0)
			pr_err("error during record");
	}
}

#endif /* DISABLE_MCOUNT_FILTER */

#ifndef FIX_PARENT_LOC
static inline unsigned long *
mcount_arch_parent_location(struct symtabs *symtabs, unsigned long *parent_loc,
			    unsigned long child_ip)
{
	return parent_loc;
}
#endif

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

int mcount_entry(unsigned long *parent_loc, unsigned long child,
		 struct mcount_regs *regs)
{
	pr_dbg("mcount_entry %lx, %lx, %lx\n", parent_loc, child, regs);
	enum filter_result filtered;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	struct uftrace_trigger tr;

	if (unlikely(mcount_should_stop()))
		return -1;

	/* Access the mtd through TSD pointer to reduce TLS overhead */
	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return -1;
	}
	else {
		if (unlikely(mtdp->recursion_guard))
			return -1;

		mtdp->recursion_guard = true;
	}

	tr.flags = 0;
	filtered = mcount_entry_filter_check(mtdp, child, &tr);
	if (filtered != FILTER_IN) {
		mtdp->recursion_guard = false;
		return -1;
	}

	if (unlikely(mtdp->in_exception)) {
		unsigned long frame_addr;

		/* same as __builtin_frame_addr(2) but avoid warning */
		frame_addr = parent_loc[-1];

		/* basic sanity check */
		if (frame_addr < (unsigned long)parent_loc)
			frame_addr = (unsigned long)(parent_loc - 1);

		mcount_rstack_reset_exception(mtdp, frame_addr);
		mtdp->in_exception = false;
	}

	/* fixup the parent_loc in an arch-dependant way (if needed) */
	parent_loc = mcount_arch_parent_location(&symtabs, parent_loc, child);

	rstack = &mtdp->rstack[mtdp->idx++];

	rstack->depth      = mtdp->record_idx;
	rstack->dyn_idx    = MCOUNT_INVALID_DYNIDX;
	rstack->parent_loc = parent_loc;
	rstack->parent_ip  = *parent_loc;
	rstack->child_ip   = child;
	rstack->start_time = mcount_gettime();
	rstack->end_time   = 0;
	rstack->flags      = 0;

	/* hijack the return address */
	*parent_loc = (unsigned long)mcount_return;

	mcount_entry_filter_record(mtdp, rstack, &tr, regs);
	mtdp->recursion_guard = false;
	return 0;
}

unsigned long mcount_exit(long *retval)
{
	pr_dbg("[mcount_exit] : %lx\n", retval);
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	unsigned long retaddr;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		/* mcount_finish() called in the middle */
		if (mcount_should_stop())
			return mtd.rstack[--mtd.idx].parent_ip;

		assert(mtdp);
	}

	mtdp->recursion_guard = true;

	rstack = &mtdp->rstack[mtdp->idx - 1];

	rstack->end_time = mcount_gettime();
	mcount_exit_filter_record(mtdp, rstack, retval);

	retaddr = rstack->parent_ip;
	// set_break_point(restored_bp);	

	compiler_barrier();

	mtdp->idx--;
	mtdp->recursion_guard = false;

	return retaddr;
}

static int cygprof_entry(unsigned long parent, unsigned long child)
{
	enum filter_result filtered;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	struct uftrace_trigger tr = {
		.flags = 0,
	};

	if (unlikely(mcount_should_stop()))
		return -1;

	/* Access the mtd through TSD pointer to reduce TLS overhead */
	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return -1;
	}
	else {
		if (unlikely(mtdp->recursion_guard))
			return -1;

		mtdp->recursion_guard = true;
	}

	filtered = mcount_entry_filter_check(mtdp, child, &tr);

	if (unlikely(mtdp->in_exception)) {
		unsigned long *frame_ptr;
		unsigned long frame_addr;

		frame_ptr = __builtin_frame_address(0);
		frame_addr = *frame_ptr;  /* XXX: probably dangerous */

		/* basic sanity check */
		if (frame_addr < (unsigned long)frame_ptr)
			frame_addr = (unsigned long)frame_ptr;

		mcount_rstack_reset_exception(mtdp, frame_addr);
		mtdp->in_exception = false;
	}

	/* 
	 * recording arguments and return value is not supported.
	 * also 'recover' trigger is only work for -pg entry.
	 */
	tr.flags &= ~(TRIGGER_FL_ARGUMENT | TRIGGER_FL_RETVAL | TRIGGER_FL_RECOVER);

	rstack = &mtdp->rstack[mtdp->idx++];

	/*
	 * even if it already exceeds the rstack max, it needs to increase idx
	 * since the cygprof_exit() will be called anyway
	 */
	if (filtered == FILTER_RSTACK) {
		mtdp->recursion_guard = false;
		return 0;
	}

	rstack->depth      = mtdp->record_idx;
	rstack->dyn_idx    = MCOUNT_INVALID_DYNIDX;
	rstack->parent_loc = &mtdp->cygprof_dummy;
	rstack->parent_ip  = parent;
	rstack->child_ip   = child;
	rstack->end_time   = 0;

	if (filtered == FILTER_IN) {
		rstack->start_time = mcount_gettime();
		rstack->flags      = 0;
	}
	else {
		rstack->start_time = 0;
		rstack->flags      = MCOUNT_FL_NORECORD;
	}

	mcount_entry_filter_record(mtdp, rstack, &tr, NULL);
	mtdp->recursion_guard = false;
	return 0;
}

static void cygprof_exit(unsigned long parent, unsigned long child)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;

	if (unlikely(mcount_should_stop()))
		return;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp) || mtdp->recursion_guard))
		return;

	mtdp->recursion_guard = true;

	/*
	 * cygprof_exit() can be called beyond rstack max.
	 * it cannot use mcount_check_rstack() here
	 * since we didn't decrease the idx yet.
	 */
	if (mtdp->idx > mcount_rstack_max)
		goto out;

	rstack = &mtdp->rstack[mtdp->idx - 1];

	if (!(rstack->flags & MCOUNT_FL_NORECORD))
		rstack->end_time = mcount_gettime();

	mcount_exit_filter_record(mtdp, rstack, NULL);

	compiler_barrier();

out:
	mtdp->idx--;
	mtdp->recursion_guard = false;
}

void xray_entry(unsigned long parent, unsigned long child,
		struct mcount_regs *regs)
{
	enum filter_result filtered;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	struct uftrace_trigger tr = {
		.flags = 0,
	};

	if (unlikely(mcount_should_stop()))
		return;

	/* Access the mtd through TSD pointer to reduce TLS overhead */
	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mcount_prepare();

		mtdp = get_thread_data();
		assert(mtdp);
	}
	else {
		if (unlikely(mtdp->recursion_guard))
			return;

		mtdp->recursion_guard = true;
	}

	filtered = mcount_entry_filter_check(mtdp, child, &tr);

	if (unlikely(mtdp->in_exception)) {
		unsigned long *frame_ptr;
		unsigned long frame_addr;

		frame_ptr = __builtin_frame_address(0);
		frame_addr = *frame_ptr;  /* XXX: probably dangerous */

		/* basic sanity check */
		if (frame_addr < (unsigned long)frame_ptr)
			frame_addr = (unsigned long)frame_ptr;

		mcount_rstack_reset_exception(mtdp, frame_addr);
		mtdp->in_exception = false;
	}

	/* 'recover' trigger is only for -pg entry */
	tr.flags &= ~TRIGGER_FL_RECOVER;

	rstack = &mtdp->rstack[mtdp->idx++];

	rstack->depth      = mtdp->record_idx;
	rstack->dyn_idx    = MCOUNT_INVALID_DYNIDX;
	rstack->parent_loc = &mtdp->cygprof_dummy;
	rstack->parent_ip  = parent;
	rstack->child_ip   = child;
	rstack->end_time   = 0;

	if (filtered == FILTER_IN) {
		rstack->start_time = mcount_gettime();
		rstack->flags      = 0;
	}
	else {
		rstack->start_time = 0;
		rstack->flags      = MCOUNT_FL_NORECORD;
	}

	mcount_entry_filter_record(mtdp, rstack, &tr, regs);
	mtdp->recursion_guard = false;
}

void xray_exit(long *retval)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;

	if (unlikely(mcount_should_stop()))
		return;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp) || mtdp->recursion_guard))
		return;

	mtdp->recursion_guard = true;

	/*
	 * cygprof_exit() can be called beyond rstack max.
	 * it cannot use mcount_check_rstack() here
	 * since we didn't decrease the idx yet.
	 */
	if (mtdp->idx > mcount_rstack_max)
		goto out;

	rstack = &mtdp->rstack[mtdp->idx - 1];

	if (!(rstack->flags & MCOUNT_FL_NORECORD))
		rstack->end_time = mcount_gettime();

	mcount_exit_filter_record(mtdp, rstack, retval);

	compiler_barrier();

out:
	mtdp->idx--;
	mtdp->recursion_guard = false;
}

/* save an asynchronous event */
int mcount_save_event(struct mcount_event_info *mei)
{
	struct mcount_thread_data *mtdp;

	if (unlikely(mcount_should_stop()))
		return -1;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return -1;

	if (mtdp->nr_events < MAX_EVENT) {
		int i = mtdp->nr_events++;

		mtdp->event[i].id   = mei->id;
		mtdp->event[i].time = mcount_gettime();
		mtdp->event[i].dsize = 0;
		mtdp->event[i].idx   = ASYNC_IDX;
	}

	return 0;
}

static void atfork_prepare_handler(void)
{
	struct uftrace_msg_task tmsg = {
		.time = mcount_gettime(),
		.pid = getpid(),
	};

	/* call script atfork preparation routine */
	if (SCRIPT_ENABLED && script_str)
		script_atfork_prepare();

	uftrace_send_message(UFTRACE_MSG_FORK_START, &tmsg, sizeof(tmsg));
}

static void atfork_child_handler(void)
{
	pr_dbg("atfor_child_handler\n");
	struct mcount_thread_data *mtdp;
	struct uftrace_msg_task tmsg = {
		.time = mcount_gettime(),
		.pid = getppid(),
		.tid = getpid(),
	};

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		/* we need it even if in a recursion */
		mtd.recursion_guard = false;

		mtdp = mcount_prepare();
	}

	/* update tid cache */
	mtdp->tid = tmsg.tid;
	/* flush event data */
	mtdp->nr_events = 0;

	mtdp->recursion_guard = true;

	clear_shmem_buffer(mtdp);
	prepare_shmem_buffer(mtdp);

	uftrace_send_message(UFTRACE_MSG_FORK_END, &tmsg, sizeof(tmsg));

	update_kernel_tid(tmsg.tid);

	mtdp->recursion_guard = false;
}

static void mcount_startup(void)
{
	char *pipefd_str;
	char *logfd_str;
	char *debug_str;
	char *bufsize_str;
	char *maxstack_str;
	char *threshold_str;
	char *color_str;
	char *demangle_str;
	char *plthook_str;
	char *patch_str;
	char *event_str;
	char *uftrace_pid_str;
	char *dirname;
	struct stat statbuf;
	bool nest_libcall;
	int uftrace_pid;

	if (!(mcount_global_flags & MCOUNT_GFL_SETUP) || mtd.recursion_guard)
		return;

	mtd.recursion_guard = true;

	outfp = stdout;
	logfp = stderr;

	if (pthread_key_create(&mtd_key, mtd_dtor))
		pr_err("cannot create mtd key");
	
	pipefd_str = getenv("UFTRACE_PIPE");
	logfd_str = getenv("UFTRACE_LOGFD");
	debug_str = getenv("UFTRACE_DEBUG");
	bufsize_str = getenv("UFTRACE_BUFFER");
	maxstack_str = getenv("UFTRACE_MAX_STACK");
	color_str = getenv("UFTRACE_COLOR");
	threshold_str = getenv("UFTRACE_THRESHOLD");
	demangle_str = getenv("UFTRACE_DEMANGLE");
	plthook_str = getenv("UFTRACE_PLTHOOK");
	patch_str = getenv("UFTRACE_PATCH");
	event_str = getenv("UFTRACE_EVENT");
	script_str = getenv("UFTRACE_SCRIPT");
	nest_libcall = !!getenv("UFTRACE_NEST_LIBCALL");
	uftrace_pid_str = getenv("UFTRACE_PID");
	
	page_size_in_kb = getpagesize() / KB;

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

	if (logfd_str) {
		int fd = strtol(logfd_str, NULL, 0);

		/* minimal sanity check */
		if (!fstat(fd, &statbuf)) {
			logfp = fdopen(fd, "a");
			setvbuf(logfp, NULL, _IOLBF, 1024);
		}
	}

	if (debug_str) {
		debug = strtol(debug_str, NULL, 0);
		build_debug_domain(getenv("UFTRACE_DEBUG_DOMAIN"));
	}

	if (demangle_str)
		demangler = strtol(demangle_str, NULL, 0);

	pr_dbg("initializing mcount library\n");
	pr_dbg("uftrace pipe : %s\n", pipefd_str);

	if (color_str)
		setup_color(strtol(color_str, NULL, 0));

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

	if (getenv("UFTRACE_LIST_EVENT")) {
		mcount_list_events();
		exit(0);
	}

	if (bufsize_str)
		shmem_bufsize = strtol(bufsize_str, NULL, 0);

	dirname = getenv("UFTRACE_DIR");
	if (dirname == NULL)
		dirname = UFTRACE_DIR_NAME;

	symtabs.dirname = dirname;

	mcount_exename = read_exename();
	record_proc_maps(dirname, mcount_session_name(), &symtabs);
	set_kernel_base(&symtabs, mcount_session_name());
	load_symtabs(&symtabs, NULL, mcount_exename);

	mcount_filter_init();

	if (maxstack_str)
		mcount_rstack_max = strtol(maxstack_str, NULL, 0);

	if (threshold_str)
		mcount_threshold = strtoull(threshold_str, NULL, 0);

	if (patch_str)
		mcount_dynamic_update(&symtabs, patch_str);

	if (event_str)
		mcount_setup_events(dirname, event_str);

	if (plthook_str)
		mcount_setup_plthook(mcount_exename, nest_libcall);

	if (getenv("UFTRACE_KERNEL_PID_UPDATE"))
		kernel_pid_update = true;

	pthread_atfork(atfork_prepare_handler, NULL, atfork_child_handler);

	mcount_hook_functions();

	/* initialize script binding */
	if (SCRIPT_ENABLED && script_str)
		if (script_init(script_str) < 0)
			script_str = NULL;

	compiler_barrier();
	pr_dbg("mcount setup done\n");
	mcount_global_flags &= ~MCOUNT_GFL_SETUP;
	mtd.recursion_guard = false;
}

static void mcount_cleanup(void)
{
	mcount_finish();
	destroy_dynsym_indexes();

#ifndef DISABLE_MCOUNT_FILTER
	uftrace_cleanup_filter(&mcount_triggers);
#endif
	if (SCRIPT_ENABLED && script_str)
		script_finish();

	unload_symtabs(&symtabs);

	pr_dbg("exit from libmcount\n");
}

/*
 * external interfaces
 */
#define UFTRACE_ALIAS(_func) void uftrace_##_func(void) __alias(_func)

void __visible_default __monstartup(unsigned long low, unsigned long high)
{
}

void __visible_default _mcleanup(void)
{
}

void __visible_default mcount_restore(void)
{
	struct mcount_thread_data *mtdp;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return;

	mcount_rstack_restore(mtdp);
}

void __visible_default mcount_reset(void)
{
	struct mcount_thread_data *mtdp;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return;

	mcount_rstack_reset(mtdp);
}

/*
void __visible_default __cyg_profile_func_enter(void *child, void *parent)
{
	cygprof_entry((unsigned long)parent, (unsigned long)child);
}
UFTRACE_ALIAS(__cyg_profile_func_enter);

void __visible_default __cyg_profile_func_exit(void *child, void *parent)
{
	cygprof_exit((unsigned long)parent, (unsigned long)child);
}
UFTRACE_ALIAS(__cyg_profile_func_exit);
*/

#ifndef UNIT_TEST

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
			printf("value %s\n", token);
			printf("value %s\n", value);
			setenv(key, value, 1);
			printf("setenv done\n");
			keyflag = true;
		} else {
			key = token;
			printf("key %s\n", key);
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
	printf("%ld:%ld\n", val.tv_sec, val.tv_usec);

	struct uftrace_mmap *map, *curr;
	map = symtabs.maps;
	printf("CHECK MMAP \n");
	while (map) {
		curr = map;
		map = map->next;
		// check 	
		if (curr->prot[2] == 'x') {
			uint64_t size = curr->end - curr->start;
			printf("0x%lx - 0x%lx\n", curr->start, curr->end);
			printf("SIZE : 0x%lx\n", size);
			SETRWX(curr->start, size); 
		}
	}
	struct symtab uftrace_symtab = symtabs.symtab;
	// attach to target. pray all child thread have to work correctly.

	printf("TARGET PID : %d\n", target_pid);
	// debugger_init(target_pid);
	mprotect(0x400000, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);
	int base_addr = 0x000000;

	disassembler_init();
	for(int index=0;index < uftrace_symtab.nr_sym;index++) {
		struct sym _sym = uftrace_symtab.sym[index];
		printf("[%d] %lx  %d :  %s\n", index, base_addr + _sym.addr, _sym.size, _sym.name);

		
		// at least, function need to bigger then call instruction. 
		// TODO : conform with feature.
		if (_sym.size > sizeof(g_call_insn)) {
			// set break point and save origin instruction. 
			// set_break_point(base_addr + _sym.addr);
			disassemble(_sym.addr, _sym.size);
		}
	}

	gettimeofday(&val, NULL);
	printf("%ld:%ld\n", val.tv_sec, val.tv_usec);
	pr_dbg("PLTHOOK : %lx\n", plthook_resolver_addr);
	pr_dbg("PLTHOOK : %lx\n", pltgot_addr);
	pr_dbg("Continue");
}



/*
 * Initializer and Finalizer
 */
static void __attribute__((constructor))
mcount_init(void)
{
	setup_environ_from_file();
	mcount_startup();
	test_bp();	
	//set_signal_handler();
}

static void __attribute__((destructor))
mcount_fini(void)
{
	mcount_cleanup();
}
#else  /* UNIT_TEST */

static void setup_mcount_test(void)
{
	mcount_exename = read_exename();

	pthread_key_create(&mtd_key, mtd_dtor);
}

static void finish_mcount_test(void)
{
	pthread_key_delete(mtd_key);
}

TEST_CASE(mcount_thread_data)
{
	struct mcount_thread_data *mtdp;

	setup_mcount_test();

	mtdp = get_thread_data();
	TEST_EQ(check_thread_data(mtdp), true);

	mtdp = mcount_prepare();
	TEST_EQ(check_thread_data(mtdp), false);

	TEST_EQ(get_thread_data(), mtdp);

	TEST_EQ(check_thread_data(mtdp), false);

	return TEST_OK;
}

#endif /* UNIT_TEST */
