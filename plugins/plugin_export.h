
void bind_script(script_uftrace_entry_t, script_uftrace_exit_t,
		 script_uftrace_end_t);

struct exports_funcs {
	void (*mcount_entry)(unsigned long, struct mcount_ret_stack *,
			     struct mcount_regs *);
	void (*mcount_exit)(struct mcount_ret_stack *);
	void (*mcount_startup)(struct symtabs *);
	void (*mcount_finish)(void);
	int (*plugin_init)(void);
	void (*bind_script)(script_uftrace_entry_t, script_uftrace_exit_t,
			    script_uftrace_end_t);
};
