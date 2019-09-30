#include "plugin.h"

bool _initialized = false;

__weak void plugin_mcount_entry(unsigned long child,
				struct mcount_ret_stack *rstack,
			        struct mcount_regs *regs)
{
	if (!init())
		return;

	pr_dbg("PLUGIN MCOUNT ENTRY\n");
}

__weak void plugin_mcount_exit(struct mcount_ret_stack *rstack)
{
	if (!init())
		return;

	pr_dbg("PLUGIN MCOUNT EXIT\n");
}

__weak void plugin_mcount_startup(struct symtabs *symtabs)
{
	if (!init())
		return;

	pr_dbg("PLUGIN STARTUP\n");
}

__weak void plugin_mcount_finish()
{
	if (!init())
		return;

	pr_dbg("PLUGIN FINISH\n");
}

__weak int plugin_init()
{
	_initialized = true;
	return _initialized;
}

int init()
{
	return _initialized;
}

void bind_script(script_uftrace_entry_t _script_uftrace_entry,
		 script_uftrace_exit_t _script_uftrace_exit,
		 script_uftrace_end_t _script_uftrace_end)
{
	script_uftrace_entry = _script_uftrace_entry;
	script_uftrace_exit = _script_uftrace_exit;
	script_uftrace_end = _script_uftrace_end;
}
