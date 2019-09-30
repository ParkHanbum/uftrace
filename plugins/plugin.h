#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define PR_FMT		"mcount"
#define PR_DOMAIN	DBG_MCOUNT

#include "libmcount/mcount.h"
#include "libmcount/internal.h"

#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/script.h"
#include "plugin_export.h"

script_uftrace_entry_t script_uftrace_entry;
script_uftrace_exit_t script_uftrace_exit;
script_uftrace_end_t script_uftrace_end;

void plugin_mcount_entry(unsigned long child, struct mcount_ret_stack *rstack,
                         struct mcount_regs *regs);
void plugin_mcount_exit(struct mcount_ret_stack *rstack);
void plugin_mcount_startup(struct symtabs *symtabs);
void plugin_mcount_finish();
int plugin_init();
int init();

extern bool _initialized;
extern struct exports_funcs ex_funcs;
extern void bind_script(script_uftrace_entry_t script_uftrace_entry,
			script_uftrace_exit_t script_uftrace_exit,
			script_uftrace_end_t script_uftrace_end);
