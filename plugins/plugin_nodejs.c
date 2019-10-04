/*
 *  Uftrace plugin for trace and record javascript function calling.
 */
#include "plugin.h"

// NODEJS
struct sym js_traceenter;
struct sym jsframe_printtop;
struct sym js_traceexit;
TLS FILE *stream_node;
TLS FILE *extern_file;
TLS char *js_name;
TLS size_t js_name_sz;
TLS bool js_entered;

const char *js_traceenter_name = "v8::internal::Runtime_TraceEnter";
const char *jsframe_printtop_name = "v8::internal::JavaScriptFrame::PrintTop";
const char *js_traceexit_name = "v8::internal::Runtime_TraceExit";

static int js_fn_index = 1;
int instrument_size = 0;

struct _IO_FILE *_stdout;
struct _IO_FILE *orig_stdout;

enum {
	MCOUNT_FL_JSENTER = (1U << 20),
	MCOUNT_FL_JSEXIT = (1U << 21),
};

void call_script_entry(char *name)
{
	struct script_context sc_ctx = {0};

	sc_ctx.tid       = 0;
	sc_ctx.depth     = 0;
	sc_ctx.address   = 0;
	sc_ctx.name      = name;
	sc_ctx.timestamp = mcount_gettime();

	/*
	if (rstack->end_time)
		sc_ctx.duration = rstack->end_time - rstack->start_time;

	if (has_arg_retval) {
		unsigned *argbuf = get_argbuf(mtdp, rstack);

		sc_ctx.arglen  = argbuf[0];
		sc_ctx.argbuf  = &argbuf[1];
		sc_ctx.argspec = pargs;
	}
	else {
		sc_ctx.arglen  = 0;
	}
	*/
	sc_ctx.arglen  = 0;
	script_uftrace_entry(&sc_ctx);
}

void call_script_exit(char *name)
{
	struct script_context sc_ctx = {0};

	sc_ctx.tid       = 0;
	sc_ctx.depth     = 0;
	sc_ctx.address   = 0;
	sc_ctx.name      = name;
	sc_ctx.timestamp = mcount_gettime();

	sc_ctx.arglen  = 0;
	script_uftrace_exit(&sc_ctx);
}

void record_entry_extern(char *name)
{
	char fin[1024] = {0};
	uint64_t ts = mcount_gettime();

	snprintf(fin, sizeof(fin), "\n%10ld.%09ld %4d:%*s %s { ",
		 ts / NSEC_PER_SEC, ts % NSEC_PER_SEC,
		 js_fn_index, 4, "", name);
	js_fn_index++;
	fwrite(fin, sizeof(char), strlen(fin), extern_file);
}

void plugin_mcount_entry(unsigned long child, struct mcount_ret_stack *rstack,
			 struct mcount_regs *regs)
{
	if (!init())
		return;

	// NODEJS
	if (js_traceenter.addr <= child &&
			child <= js_traceenter.addr + 30) {
		rstack->flags |= MCOUNT_FL_JSENTER;
		rstack->flags |= MCOUNT_FL_NORECORD;

		js_entered = true;
	} else if (jsframe_printtop.addr + 20 <= child &&
			child <= jsframe_printtop.addr + 26) {
		stream_node = open_memstream(&js_name, &js_name_sz);
		if (stream_node == NULL)
			pr_err("open_memstream");
		ARG2(regs) = (uintptr_t)stream_node;
	} else if (js_traceexit.addr + 0 <= child &&
			child <= js_traceexit.addr + 30) {
		rstack->flags |= MCOUNT_FL_JSEXIT;
		rstack->flags |= MCOUNT_FL_NORECORD;

		js_entered = true;
	}

	if (js_entered)
		rstack->flags |= MCOUNT_FL_NORECORD;
}

void record_exit_extern(char *name)
{
	char fin[1024] = {0};
	uint64_t ts = mcount_gettime();

	js_fn_index--;
	snprintf(fin, sizeof(fin), "\n%10ld.%09ld %4d:%*s } -> %s",
		 ts / NSEC_PER_SEC, ts % NSEC_PER_SEC,
		 js_fn_index, 4, "", name);
	fwrite(fin, sizeof(char), strlen(fin), extern_file);
}

void plugin_mcount_exit(struct mcount_ret_stack *rstack)
{
	if (!init())
		return;

	// NODEJS
	if (rstack->flags & MCOUNT_FL_JSENTER) {
		fclose(stream_node);
		rstack->flags &= ~MCOUNT_FL_JSENTER;
		rstack->flags &= ~MCOUNT_FL_NORECORD;
		record_entry_extern(js_name);
		call_script_entry(js_name);
		free(js_name);

		js_entered = false;
	} else if (rstack->flags & MCOUNT_FL_JSEXIT) {
		rstack->flags &= ~MCOUNT_FL_JSEXIT;
		rstack->flags &= ~MCOUNT_FL_NORECORD;
		record_exit_extern("");
		call_script_exit("");

		js_entered = false;
	}
}

void open_extern()
{
	char *external;
	char *dirname;

	dirname = getenv("UFTRACE_DIR");
	if (dirname == NULL)
		dirname = UFTRACE_DIR_NAME;
	xasprintf(&external, "%s/%s", dirname, "extern.dat");
	extern_file = fopen(external, "w+");
	free(external);
}

int find_syms(struct symtabs *symtabs)
{
	// NODEJS
	struct uftrace_mmap *map;

	for_each_map(symtabs, map) {
		if (map->mod != NULL) {
			struct symtab *symtab = &map->mod->symtab;
			for (size_t i = 0; i < symtab->nr_sym; i++) {
				struct sym *sym = &symtab->sym[i];

				if (!strcmp(js_traceenter_name, sym->name)) {
					memcpy(&js_traceenter, sym, sizeof(struct sym));
					js_traceenter.addr += map->start;
				} else if (!strcmp(jsframe_printtop_name, sym->name)) {
					memcpy(&jsframe_printtop, sym, sizeof(struct sym));
					jsframe_printtop.addr += map->start;
				} else if (!strcmp(js_traceexit_name, sym->name)) {
					memcpy(&js_traceexit, sym, sizeof(struct sym));
					js_traceexit.addr += map->start;
				}
			}
		}
	}

	if (jsframe_printtop.name == NULL || js_traceexit.name == NULL
					  || js_traceenter.name == NULL) {
		return -1;
	}

	return 0;
}

void plugin_mcount_startup(struct symtabs *symtabs)
{
	if (!init())
		return;

	char *patch_str;

	fprintf(stderr, "nodejs plugin startup \n");

	open_extern();
	if (find_syms(symtabs) < 0) {
		pr_err("cannot use this plugin without these symbols : %s %s",
			jsframe_printtop_name, js_traceexit_name);
	}

	patch_str = getenv("UFTRACE_PATCH");
	if (!patch_str)
		instrument_size = 0;

	if (script_uftrace_entry == NULL || script_uftrace_exit == NULL 
					 || script_uftrace_end == NULL)
		_initialized = false;
}

void plugin_mcount_finish()
{
	if (!init())
		return;

	if (extern_file != NULL)
		fclose(extern_file);

	if (stream_node != NULL)
		fclose(stream_node);
}

struct exports_funcs ex_funcs = {
	plugin_mcount_entry, plugin_mcount_exit,
	plugin_mcount_startup, plugin_mcount_finish,
	plugin_init, bind_script
};
