
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "utils/hashmap.h"
#include "utils/ptrace.h"
#include "utils/utils.h"

Hashmap *map;
pid_t target_pid;
struct user_regs_struct oldregs, regs;

// BREAKPOINT_ADDR_TYPE definition must be change at other architecture.
#define BREAKPOINT_ADDR_TYPE uint64_t 
#define BREAKPOINT_ORIGIN_DATA_TYPE unsigned char

#define bpa_t BREAKPOINT_ADDR_TYPE
#define bpd_t BREAKPOINT_ORIGIN_DATA_TYPE

bpa_t bp_addr_array[1024] = {0, };
bpd_t bp_data_array[1024] = {0, };

int addr_array_pos = 0;
int data_array_pos = 0;

int hashmapBpHash(void* key) {
	// Return the key value itself.
	return *((bpa_t *) key);
}

bool hashmapBpEquals(void* keyA, void* keyB) {
	bpa_t a = *((bpa_t*) keyA);
	bpa_t b = *((bpa_t*) keyB);
	return a == b;
}

void bp_hashmap_init() 
{
	map = hashmapCreate(10, hashmapBpHash, hashmapBpEquals);
	// TODO :: for proof of concept,
	mprotect(0x400000, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);
}

void bp_hashmap_finit()
{
	hashmapFree(map);
}

void debugger_init(pid_t target)
{
	target_pid = target;
	//ptrace_attach(target_pid);
	bp_hashmap_init();
}

void debugger_free() 
{
	bp_hashmap_finit();
	ptrace_detach(target_pid);
}

void bp_hashmap_put(bpa_t key, bpd_t value) 
{
	bp_addr_array[addr_array_pos] = key;
	bp_data_array[data_array_pos] = value;		

	hashmapPut(map, &bp_addr_array[addr_array_pos], &bp_data_array[data_array_pos]);
	addr_array_pos++; data_array_pos++; 
}

bool iterator_int_key(void* key, void* value, void* context)
{
        printf("KEY : %x, VALUE : %lx\n", *(bpa_t *)key, *(bpd_t *)value);
        return true;
}

void print_hashmap() 
{
	hashmapForEach(map, iterator_int_key, map);
}

void set_break_point(uintptr_t addr)
{
	pr_dbg("SET BP\n");
	unsigned char BREAKPOINT_INSTRUCTION = 0xcc;
	unsigned char origin_data;
	uint32_t _data;
	pr_dbg("ADDRESS : %x\n", addr);
	_data = *(uint32_t *)addr;
	pr_dbg("DATA : %x\n", _data);
	//ptrace_read(target_pid, addr, &_data, sizeof(_data)); 
	origin_data = _data & 0xff;

	bp_hashmap_put(addr, origin_data);
	uint32_t _data_with_bp = ((_data & ~0xff) | BREAKPOINT_INSTRUCTION);
	printf("ADDR : %x\t READ : %x\t BP : %x\t ORIGIN : %x\n", addr, _data, _data_with_bp, origin_data);

	// TODO : this hard-cord must fixed.
	mprotect(addr, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);
	*(uint32_t *)addr = _data_with_bp;
	//ptrace_write(target_pid, addr, &_data_with_bp, sizeof(_data_with_bp));
}

void remove_break_point(long addr)
{
	pr_dbg("REMOVE BP at %x\n", addr);
	
	bpd_t saved_data = *(bpd_t *)hashmapGet(map, &addr);
	pr_dbg("SAVED DATA : %x\n", saved_data);
	char data = *(char *)addr;
	pr_dbg("DATA AT BP : %x\n", data & 0xff); 
	char restored_data = saved_data;
	pr_dbg("RESTORE DATA : %lx\n", restored_data);
	
	*(char *)addr = restored_data;
}


