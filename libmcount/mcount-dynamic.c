/*
 * support dynamic tracing for uftrace.
 *
 * Copyright (C) 2018, global frontier at kosslab.  
 * Hanbum Park <kese111@gmail.com>
 *
 * Released under the GPL v2.
 */

/*
 we replace instructions over 6bytes from start of function 
 to call '__dentry__' that seems similar like '__fentry__'.

 while replacing, After adding the generated instruction which 
 returns to the address of the original instruction end, 
 save it in the heap. 

 for example:

  4005f0:       31 ed                   xor     %ebp,%ebp
  4005f2:       49 89 d1                mov     %rdx,%r9
  4005f5:       5e                      pop     %rsi 

 will changed like this :

  4005f0	call qword ptr [rip + 0x200a0a] # 0x601000
  
 and keeping original instruction :
 
 Original Instructions---------------
   f1cff0:	xor ebp, ebp            
   f1cff2:	mov r9, rdx             
   f1cff5:	pop rsi                 
 Generated Instruction to return----- 
   f1cff6:	jmp qword ptr [rip]     
   f1cffc:	QW 0x00000000004005f6   
  
 In the original case, address 0x601000 has a dynamic symbol 
 start address. It is also the first element in the GOT array.
 while initializing the mcount library, we will replace it with 
 the address of the function '__dentry__'. so, the changed 
 instruction will be calling '__dentry__'. 
 
 '__dentry__' has a similar function like '__fentry__'. 
 the other thing is that it returns to original instructions
 we keeping. it makes it possible to execute the original 
 instructions and return to the address at the end of the original 
 instructions. Thus, the execution will goes on.
 
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
#define PR_FMT     "mcount-dynamic"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/script.h"
#include "utils/debugger.h"

// set write permission to memory 
#define SETRWX(addr, len)   mprotect((void*)((addr) &~ 0xFFF),\
                                     (len) + ((addr) - ((addr) &~ 0xFFF)),\
                                     PROT_READ | PROT_EXEC | PROT_WRITE)
#define SETROX(addr, len)   mprotect((void*)((addr) &~ 0xFFF),\
                                     (len) + ((addr) - ((addr) &~ 0xFFF)),\
                                     PROT_READ | PROT_EXEC)

// for Capstone 
csh csh_handle;
extern cs_err cs_open(cs_arch arch, cs_mode mode, csh *handle);

extern void mtd_dtor(void *arg);
extern void fentry_return(void);
extern unsigned long plthook_resolver_addr;

// 0 of pltgot_addr is replaced with record function. 
extern unsigned long pltgot_addr;

/* pipe file descriptor to communite to uftrace */
extern int pfd;

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

/* time filter in nsec */
uint64_t mcount_threshold;

struct address_entry {
	uintptr_t addr;
	uintptr_t saved_addr;
	struct list_head list;
};

static LIST_HEAD(address_list);


/*
 TODO : the following instructions should be generated 
 for each architecure.

 
 g_call_insn : g_call_insn be used to calling the __dentry__.
 when replacing the instuctions that located start of the function, 
 calculating offset between there and first element of Global offset 
 table. after calculating, we generate the call instruction to calling 
 the '__dentry__' function with calculated relative offset.
 because there is no instruction to jumping 64bit address directly.
 
 [Example]
  4005f0	call qword ptr [rip + 0x200a0a] # 0x601000
 
 
 g_jmp_insn : g_jmp_insn be used to return to address end of patched 
 instruction. after saved original instructions has been executed, 
 the address end of patched instruction that has been added while saving 
 original instruction will used by g_jmp_insn to move the control-flow 
 to end of patched instruction. 

 [Example]
   f1cff6:	jmp qword ptr [rip]     
   f1cffc:	QW 0x00000000004005f6   
  
 
*/
static unsigned char g_call_insn[] =  
{0xFF, 0x15, 0x00, 0x00, 0x00, 0x00};

static unsigned char g_jmp_insn[] = 
{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};

static const int g_call_insn_size = sizeof(g_call_insn); 

typedef unsigned char* puchar;

static void print_string_hex(char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	pr_dbg("%s", comment);
	for (c = str; c < str + len; c++) {
		pr_dbg("0x%02x ", *c & 0xff);
	}

	pr_dbg("\n");
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

/*
Patch the instruction to the address as given for arguments.
*/
puchar patch_code(uintptr_t addr, unsigned char* call_insn, unsigned int code_size) 
{
	// calc relative address of addr between pltgot_addr;
	unsigned long rel_addr = pltgot_addr - addr - g_call_insn_size;
	puchar ptr = &rel_addr;
	puchar save_addr, code_addr;

	// increase code_size to include g_jmp_insn and the address 
	// patched instruction end for allcation.
	uint32_t saved_code_size = code_size + sizeof(g_jmp_insn) + sizeof(long);
	int i;

	// make instruction have to patched. 	
	for(i=0;i < 4;i++) {
		pr_dbg2("%02x\n", *(ptr+i));
		// FF 15 XX XX XX XX 
		call_insn[2 + i] = *(ptr+i); 
	}
	
	if (debug) {
		print_string_hex("INSTRUMENT INSTRUCTION : ", call_insn, g_call_insn_size);
	}

	uintptr_t alloc_addr = malloc(saved_code_size);	
	memset(alloc_addr, NULL, saved_code_size); 
	SETRWX(alloc_addr, saved_code_size);

	save_addr = (puchar)alloc_addr;
	code_addr = (puchar)addr;

	// At least 6 bytes at prologue of function will be replaced. 
	// if we need to replace over the 6bytes, replace it with 
	// NOP instruction.
	for(i=0;i < code_size;i++) {
		save_addr[i] = code_addr[i];
		if (i > g_call_insn_size -1) {
			pr_dbg2("patching... : %x to %x \n", code_addr[i], 0x90);
			code_addr[i] = 0x90; 
		} else {
			pr_dbg2("patching... : %x to %x \n", code_addr[i], call_insn[i]);
			code_addr[i] = call_insn[i];	
		}
	}
	
	// add instruction to return to end of patched instruction. 
	save_addr[code_size+0] = g_jmp_insn[0];
	save_addr[code_size+1] = g_jmp_insn[1];
	save_addr[code_size+2] = g_jmp_insn[2];
	save_addr[code_size+3] = g_jmp_insn[3];
	save_addr[code_size+4] = g_jmp_insn[4];
	save_addr[code_size+5] = g_jmp_insn[5];
	
	// append the last address of patched instruction as data.
	*((uintptr_t *)(&save_addr[code_size+6])) = &code_addr[code_size];
	pr_dbg2("RETURN ADDRESS : %llx\n", &code_addr[code_size]);
	
	if (debug) {
		print_disassemble(save_addr, saved_code_size); 
		print_disassemble(addr, code_size);
	}
	
	return save_addr;
}

#define CAN_USE_DYNAMIC 0x1
#define NOT_USE_DYNAMIC 0x2

/*
Determines whether the instruction can be moved. 
Returns whether dynamics can be used or not based on the result.
*/
// TODO: following function must be implemented in each architecture. 
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

/*
while instrument g_call_insn to prologue of the function, 
save original instructions to allocated heap space.
*/
int dynamic_instrument(uintptr_t address, uint32_t insn_size) 
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
		// TODO : we need error handling here.
		pr_err("GRRRRRRRRRRRRRRRRRRRRR......\n");
	}
}

/*
initializing capstone the disassembler. 
*/
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

#define INSTRUMENT_ERR_INSTRUCTION		0x0001
#define INSTRUMENT_ERR_OTHERWISE		0x0002
#define INSTRUMENT_SUCCESS			0x0000

/*
make sure that the instructions at prologue of function to be patched 
can be moved to another address. if possible, enable dynamic tracing 
feature. 
*/
int instrument(uintptr_t address, uint32_t size) 
{
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
		if (code_size > g_call_insn_size -1) {
			break;
		} 
	}
	
	dynamic_instrument(address, code_size);
	
	
	// prints "original code address : saved address" pair.
	struct address_entry* entry;
	if (debug) {
		pr_dbg("=================================\n");
		list_for_each_entry(entry, &address_list, list) {
			pr_dbg("%lx : %lx\n", entry->addr, entry->saved_addr);
		}
	}

	cs_free(insn, count);	
	return INSTRUMENT_SUCCESS; 
}

uintptr_t find_origin_code_addr(uintptr_t addr)
{
	uintptr_t patched_addr, ret_addr = NULL;
	patched_addr = addr - g_call_insn_size;
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

/*
call the fucntion mcount_entry to record tracing data. 
if function mcount_entry have worked well, find the address that 
original code saved to replace return address. and return it. 
if not, return 0. 

*/
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
		// TODO : we must handle ERROR case.
		// at here, 0 mean there is no patched. 
		return 0;
	}
}

/*
reads the configuration key and values stored in 
'/tmp/uftrace_environ_file' and sets it to the current process.
*/
static void setup_environ_from_file() {
	int fd;
	char buf[1024] = {0,};
	bool keyflag = false;
	char* key, *value;

	fd = open("/tmp/uftrace_environ_file", O_RDONLY);
	
	if (fd < 0) return -1;

	read(fd, buf, 1024);
	close(fd);

	// TODO  
	// 1. token or value can be empty. 
	// 2. a value can include another token.
	char* token = strtok(buf, "=\n");
	keyflag = true;
	do {
		if (!keyflag) {
			value = token;
			pr_dbg2("token %s\n", token);
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

/*
set the write permission to memory area have executable permission.
*/
void set_write_perm_to_text() 
{
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

}

/*
to enable dynamic tracing, instrument the g_call_insn to the prologue
of the function.
*/
void enable_dynamic_trace_each_function() 
{
	int index;
	struct symtab uftrace_symtab = symtabs.symtab;
	// do dynamic instrumentation to each function.
	for(index=0;index < uftrace_symtab.nr_sym;index++) {
		struct sym _sym = uftrace_symtab.sym[index];
		pr_dbg("[%d] %lx  %d :  %s\n", index, _sym.addr, _sym.size, _sym.name);
		// exclude function.
		// TODO : we need additional logic to handle this.  
		// reference follow link 
		// https://github.com/ParkHanbum/uftrace/issues/5
		if (!strncmp(_sym.name, "_start", 6)) {
			continue;
		}
	
		// at least to use dynamic tracing the target function 
		// must bigger than g_call_insn. 	
		if (_sym.size > sizeof(g_call_insn)) {
			instrument(_sym.addr, _sym.size);
		}
	}
}

/*
enable dynamic tracing feature. 
*/
void enable_dynamic_trace()
{
	char *dirname;
	int target_pid = getpid();

	// attach to target. pray all child thread have to work correctly.
	pr_dbg("TARGET PID : %d\n", target_pid);

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
	
	// intialize capstone
	disassembler_init();
	// append write permission to each text section.
	set_write_perm_to_text();
	// enable dynamic tracing to each function.
	enable_dynamic_trace_each_function();

	gettimeofday(&val, NULL);
	pr_dbg2("%ld:%ld\n", val.tv_sec, val.tv_usec);
	pr_dbg("PLTHOOK : %lx %lx\n", plthook_resolver_addr, pltgot_addr);
}


#ifndef UNIT_TEST

/*
previous mcount_startup() the contructor.
*/
void pre_startup()
{
	setup_environ_from_file();
}

/*
configuration for dynamic tracing.
*/
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

	pipefd_str = getenv("UFTRACE_PIPE");	
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

/*
post mcount_startup() the constructor.
*/
void post_startup()
{
	config_for_dynamic();		
	enable_dynamic_trace();	
}

#else  /* UNIT_TEST */

// TODO : make test and get the grade A+.

#endif /* UNIT_TEST */
