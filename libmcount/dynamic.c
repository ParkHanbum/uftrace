/*
 * INSTRUMENTED CODE LAYOUT
 *
 * Func offset | Instrumented code
 * --------------------------------
 * 	   0x0 | Call Trampoline
 * 	   0x6 | nop
 * 	   0x7 | nop
 *
 * we must use starting address of function when
 * -. store original code to hashmap
 * -. find original code from hashmap
 * -. unpatch function
 */
#include <string.h>
#include <stdint.h>
#include <link.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/rbtree.h"
#include "utils/list.h"
#include "utils/hashmap.h"

static struct mcount_dynamic_info *mdinfo;
static struct mcount_dynamic_stats {
	int total;
	int failed;
	int skipped;
	int nomatch;
	int unpatch;
} stats;

#define PAGE_SIZE   4096
#define CODE_CHUNK  (PAGE_SIZE * 8)

struct code_page {
	struct list_head	list;
	void			*page;
	int			pos;
	bool			frozen;
};

static LIST_HEAD(code_pages);

static struct Hashmap *code_hmap;

/* at least, function size must be greater than this */
static uint64_t min_size = 0;

/* disassembly engine for dynamic code patch */
static struct mcount_disasm_engine disasm;

static struct list_head *instrument_ml;

struct patt_list {
	struct list_head list;
	struct uftrace_pattern patt;
	char *module;
	bool positive;
};

struct module_list {
	struct list_head list;
	struct list_head patt_list;
	char *modname;
};


static struct mcount_orig_insn *create_code(struct Hashmap *map,
					    unsigned long addr)
{
	struct mcount_orig_insn *entry;

	entry = xmalloc(sizeof *entry);
	entry->addr = addr;
	if (hashmap_put(code_hmap, (void *)entry->addr, entry) == NULL)
		pr_err("code map allocation failed");
	return entry;
}

static struct mcount_orig_insn *lookup_code(struct Hashmap *map,
					    unsigned long addr)
{
	struct mcount_orig_insn *entry;

	entry = hashmap_get(code_hmap, (void *)addr);
	return entry;
}

static struct code_page *alloc_codepage(void)
{
	struct code_page *cp = NULL;

	cp = xzalloc(sizeof(*cp));
	cp->page = mmap(NULL, CODE_CHUNK, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (cp->page == MAP_FAILED)
		pr_err("mmap code page failed");

	cp->pos = 0;
	list_add_tail(&cp->list, &code_pages);
	return cp;
}

void mcount_save_code(struct mcount_disasm_info *info,
		      void *jmp_insn, unsigned jmp_size)
{
	struct code_page *cp = NULL;
	struct mcount_orig_insn *orig;
	int patch_size;

	if (unlikely(info->modified)) {
		/* it needs to save original instructions as well */
		int orig_size = ALIGN(info->orig_size, 16);
		int copy_size = ALIGN(info->copy_size + jmp_size, 16);
		patch_size = ALIGN(copy_size + orig_size, 32);
	}
	else {
		patch_size = ALIGN(info->copy_size + jmp_size, 32);
	}

	if (!list_empty(&code_pages))
		cp = list_last_entry(&code_pages, struct code_page, list);

	if (cp == NULL || (cp->pos + patch_size > CODE_CHUNK)) {
		cp = alloc_codepage();
	}

	orig = lookup_code(code_hmap, info->addr);
	if (orig == NULL)
		orig = create_code(code_hmap, info->addr);

	/*
	 * if dynamic patch has been processed before, cp be frozen by
	 * calling freeze_code. so, when reaching here from the
	 * mcount_handle_dlopen, cp unwriteable.
	 */
	if (cp->frozen) {
		/* [Caution]
		 * even if a little memory loss occurs, it can be dangerous
		 * that to re-assigned write and execute permission to exist
		 * codepage, so be sure to allocate new memory.
		 */
		cp = alloc_codepage();
	}

	orig->insn = cp->page + cp->pos;
	orig->orig = orig->insn;
	orig->orig_size = info->orig_size;
	orig->insn_size = info->copy_size + jmp_size;

	if (info->modified) {
		/* save original instructions before modification */
		orig->orig = orig->insn + patch_size - ALIGN(info->orig_size, 16);
		memcpy(orig->orig, (void *)info->addr, info->orig_size);
	}

	memcpy(orig->insn, info->insns, info->copy_size);
	memcpy(orig->insn + info->copy_size, jmp_insn, jmp_size);

	cp->pos += patch_size;
}

void mcount_freeze_code(void)
{
	struct code_page *cp;

	list_for_each_entry(cp, &code_pages, list) {
		mprotect(cp->page, CODE_CHUNK, PROT_READ|PROT_EXEC);
		cp->frozen = true;
	}
}

void *mcount_find_code(unsigned long addr)
{
	struct mcount_orig_insn *orig;

	orig = lookup_code(code_hmap, addr);
	if (orig == NULL)
		return NULL;

	return orig->insn;
}

struct mcount_orig_insn * mcount_find_insn(unsigned long addr)
{
	return lookup_code(code_hmap, addr);
}

static bool release_code(void *key, void *value, void *ctx)
{
	hashmap_remove(code_hmap, key);
	free(value);
	return true;
}

/* not actually called for safety reason */
void mcount_release_code(void)
{
	hashmap_for_each(code_hmap, release_code, NULL);
	hashmap_free(code_hmap);

	while (!list_empty(&code_pages)) {
		struct code_page *cp;

		cp = list_first_entry(&code_pages, struct code_page, list);
		list_del(&cp->list);
		munmap(cp->page, CODE_CHUNK);
		free(cp);
	}
}

/* dummy functions (will be overridden by arch-specific code) */
__weak int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	return -1;
}

__weak void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
}

__weak int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			     struct mcount_disasm_engine *disasm,
			     unsigned min_size)
{
	return -1;
}

__weak int mcount_unpatch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			       struct mcount_disasm_engine *disasm)
{
	return -1;
}

__weak void mcount_arch_find_module(struct mcount_dynamic_info *mdi,
				    struct symtab *symtab)
{
	mdi->arch = NULL;
}

__weak void mcount_arch_dynamic_recover(struct mcount_dynamic_info *mdi,
					struct mcount_disasm_engine *disasm)
{
}

__weak void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
}

__weak void mcount_disasm_finish(struct mcount_disasm_engine *disasm)
{
}

struct find_module_data {
	struct symtabs *symtabs;
	bool needs_modules;
};

static struct mcount_dynamic_info * create_mdi(unsigned long baseaddr,
					       unsigned long textaddr,
					       unsigned int textsize)
{
	struct mcount_dynamic_info *mdi;

	mdi = xzalloc(sizeof(*mdi));

	mdi->base_addr = baseaddr;
	mdi->text_addr = textaddr;
	mdi->text_size = textsize;

	INIT_LIST_HEAD(&mdi->bad_syms);

	return mdi;
}

static struct module_list *find_module_list(char *modname)
{
	struct module_list *ml;

	list_for_each_entry(ml, instrument_ml, list) {
		if (!strncmp(ml->modname, modname, strlen(modname)))
			return ml;
	}

	return NULL;
}


static struct module_list *add_module_list(char *modname)
{
	struct module_list *ml;

	if (instrument_ml == NULL) {
		instrument_ml = xmalloc(sizeof(*instrument_ml));
		INIT_LIST_HEAD(instrument_ml);
	}

	ml = find_module_list(modname);

	if (ml == NULL) {
		ml = xmalloc(sizeof(*ml));
		ml->modname = xstrdup(modname);
		INIT_LIST_HEAD(&ml->patt_list);
		list_add_tail(&ml->list, instrument_ml);
	}

	return ml;
}

/* callback for dl_iterate_phdr() */
static int find_dynamic_module(struct dl_phdr_info *info, size_t sz, void *data)
{
	struct mcount_dynamic_info *mdi;
	struct find_module_data *fmd = data;
	struct symtabs *symtabs = fmd->symtabs;
	struct uftrace_mmap *map;
	bool base_addr_set = false;
	unsigned i;
	unsigned long base_addr = 0, text_addr = 0;
	unsigned int text_size = 0;

	mdi = xzalloc(sizeof(*mdi));

	for (i = 0; i < info->dlpi_phnum; i++) {
		if (info->dlpi_phdr[i].p_type != PT_LOAD)
			continue;

		if (!base_addr_set) {
			base_addr = info->dlpi_phdr[i].p_vaddr;
			base_addr_set = true;
		}

		if (!(info->dlpi_phdr[i].p_flags & PF_X))
			continue;

		/* find address and size of code segment */
		text_addr = info->dlpi_phdr[i].p_vaddr;
		text_size = info->dlpi_phdr[i].p_memsz;
		break;
	}
	base_addr += info->dlpi_addr;
	text_addr += info->dlpi_addr;

	mdi = create_mdi(base_addr, text_addr, text_size);

	map = find_map(symtabs, mdi->base_addr);
	if (map && map->mod) {
		mdi->map = map;
		mcount_arch_find_module(mdi, &map->mod->symtab);

		mdi->next = mdinfo;
		mdinfo = mdi;
	}
	else {
		free(mdi);
	}

	return !fmd->needs_modules;
}

static void prepare_dynamic_update(struct symtabs *symtabs,
				   bool needs_modules)
{
	struct find_module_data fmd = {
		.symtabs = symtabs,
		.needs_modules = needs_modules,
	};
	int hash_size = symtabs->exec_map->mod->symtab.nr_sym * 3 / 4;

	if (needs_modules)
		hash_size *= 2;

	code_hmap = hashmap_create(hash_size, hashmap_ptr_hash,
				   hashmap_ptr_equals);
	mcount_disasm_init(&disasm);
	dl_iterate_phdr(find_dynamic_module, &fmd);
}

struct mcount_dynamic_info *setup_trampoline(struct uftrace_mmap *map)
{
	struct mcount_dynamic_info *mdi;

	for (mdi = mdinfo; mdi != NULL; mdi = mdi->next) {
		if (map == mdi->map)
			break;
	}

	if (mdi != NULL && mdi->trampoline == 0) {
		if (mcount_setup_trampoline(mdi) < 0)
			mdi = NULL;
	}

	return mdi;
}


static bool match_pattern_list(struct list_head *patterns,
			       struct uftrace_mmap *map,
			       char *sym_name)
{
	struct patt_list *pl;
	bool ret = false;

	list_for_each_entry(pl, patterns, list) {
		char *libname = basename(map->libname);

		if (strncmp(libname, pl->module, strlen(pl->module)))
			continue;

		if (match_filter_pattern(&pl->patt, sym_name))
			ret = pl->positive;
	}

	return ret;
}

static void patch_func_matched(struct mcount_dynamic_info *mdi,
			       struct uftrace_mmap *map)
{
	bool found = false;
	struct symtab *symtab;
	bool csu_skip;
	unsigned i, k;
	struct sym *sym;
	struct module_list *ml;
	/* skip special startup (csu) functions */
	const char *csu_skip_syms[] = {
		"_start",
		"__libc_csu_init",
		"__libc_csu_fini",
	};

	ml = find_module_list(map->libname);
	if (ml == NULL)
		return;

	symtab = &map->mod->symtab;

	for (i = 0; i < symtab->nr_sym; i++) {
		sym = &symtab->sym[i];

		csu_skip = false;
		for (k = 0; k < ARRAY_SIZE(csu_skip_syms); k++) {
			if (!strcmp(sym->name, csu_skip_syms[k])) {
				csu_skip = true;
				break;
			}
		}
		if (csu_skip)
			continue;

		if (sym->type != ST_LOCAL_FUNC &&
		    sym->type != ST_GLOBAL_FUNC)
			continue;

		if (!match_pattern_list(&ml->patt_list, map, sym->name)) {
			if (mcount_unpatch_func(mdi, sym, &disasm) == 0)
				stats.unpatch++;
			continue;
		}

		found = true;
		switch (mcount_patch_func(mdi, sym, &disasm, min_size)) {
			case INSTRUMENT_FAILED:
				stats.failed++;
				break;
			case INSTRUMENT_SKIPPED:
				stats.skipped++;
				break;
			case INSTRUMENT_SUCCESS:
			default:
				break;
		}
		stats.total++;
	}

	if (!found)
		stats.nomatch++;
}

static int do_dynamic_update(struct symtabs *symtabs, char *patch_funcs,
			     enum uftrace_pattern_type ptype)
{
	struct uftrace_mmap *map;
	struct strv funcs = STRV_INIT;
	char *def_mod;
	char *name;
	int j;
	struct patt_list *pl;
	struct module_list *ml;
	bool all_negative = true;

	if (patch_funcs == NULL)
		return 0;

	def_mod = basename(symtabs->exec_map->libname);
	strv_split(&funcs, patch_funcs, ";");

	strv_for_each(&funcs, name, j) {
		char *delim;

		pl = xzalloc(sizeof(*pl));

		if (name[0] == '!')
			name++;
		else {
			pl->positive = true;
			all_negative = false;
		}

		delim = strchr(name, '@');
		if (delim == NULL) {
			pl->module = xstrdup(def_mod);
		}
		else {
			*delim = '\0';
			pl->module = xstrdup(++delim);
		}

		ml = add_module_list(pl->module);

		init_filter_pattern(ptype, &pl->patt, name);
		list_add_tail(&pl->list, &ml->patt_list);
	}

	/* prepend match-all pattern, if all patterns are negative */
	if (all_negative) {
		pl = xzalloc(sizeof(*pl));
		pl->positive = true;
		pl->module = xstrdup(def_mod);

		if (ptype == PATT_REGEX)
			init_filter_pattern(ptype, &pl->patt, ".");
		else
			init_filter_pattern(PATT_GLOB, &pl->patt, "*");

		// add pl to all modules
		// list_add(&pl->list, &patterns);
	}

	for_each_map(symtabs, map) {
		struct mcount_dynamic_info *mdi;

		/* TODO: filter out unsuppported libs */
		mdi = setup_trampoline(map);
		if (mdi == NULL)
			continue;

		patch_func_matched(mdi, map);
	}

	if (stats.failed + stats.skipped + stats.nomatch == 0) {
		pr_dbg("patched all (%d) functions in '%s'\n",
		       stats.total, basename(symtabs->filename));
	}

	strv_free(&funcs);
	return 0;
}

static void finish_dynamic_update(void)
{
	struct mcount_dynamic_info *mdi, *tmp;

	mdi = mdinfo;
	while (mdi) {
		tmp = mdi->next;

		mcount_arch_dynamic_recover(mdi, &disasm);
		mcount_cleanup_trampoline(mdi);
		free(mdi);

		mdi = tmp;
	}

	mcount_freeze_code();
}

/* do not use floating-point in libmcount */
static int calc_percent(int n, int total, int *rem)
{
	int quot = 100 * n / total;

	*rem = (100 * n - quot * total) * 100 / total;
	return quot;
}

int mcount_dynamic_update(struct symtabs *symtabs, char *patch_funcs,
			  enum uftrace_pattern_type ptype)
{
	int ret = 0;
	char *size_filter;
	bool needs_modules = !!strchr(patch_funcs, '@');

	prepare_dynamic_update(symtabs, needs_modules);

	size_filter = getenv("UFTRACE_PATCH_SIZE");
	if (size_filter != NULL)
		min_size = strtoul(size_filter, NULL, 0);

	ret = do_dynamic_update(symtabs, patch_funcs, ptype);

	if (stats.total && stats.failed) {
		int success = stats.total - stats.failed - stats.skipped;
		int r, q;

		pr_dbg("dynamic patch stats for '%s'\n",
		       basename(symtabs->filename));
		pr_dbg("   total: %8d\n", stats.total);
		q = calc_percent(success, stats.total, &r);
		pr_dbg(" patched: %8d (%2d.%02d%%)\n", success, q, r);
		q = calc_percent(stats.failed, stats.total, &r);
		pr_dbg("  failed: %8d (%2d.%02d%%)\n", stats.failed, q, r);
		q = calc_percent(stats.skipped, stats.total, &r);
		pr_dbg(" skipped: %8d (%2d.%02d%%)\n", stats.skipped, q, r);
		pr_dbg("no match: %8d\n", stats.nomatch);
	}

	finish_dynamic_update();
	return ret;
}

struct dynamic_bad_symbol * mcount_find_badsym(struct mcount_dynamic_info *mdi,
					       unsigned long addr)
{
	struct sym *sym;
	struct dynamic_bad_symbol *badsym;

	sym = find_sym(&mdi->map->mod->symtab, addr - mdi->map->start);
	if (sym == NULL)
		return NULL;

	list_for_each_entry(badsym, &mdi->bad_syms, list) {
		if (badsym->sym == sym)
			return badsym;
	}

	return NULL;
}

bool mcount_add_badsym(struct mcount_dynamic_info *mdi, unsigned long callsite,
		       unsigned long target)
{
	struct sym *sym;
	struct dynamic_bad_symbol *badsym;

	if (mcount_find_badsym(mdi, target))
		return true;

	sym = find_sym(&mdi->map->mod->symtab, target - mdi->map->start);
	if (sym == NULL)
		return true;

	/* only care about jumps to the middle of a function */
	if (sym->addr + mdi->map->start == target)
		return false;

	pr_dbg2("bad jump: %s:%lx to %lx\n", sym ? sym->name : "<unknown>",
		callsite - mdi->map->start, target - mdi->map->start);

	badsym = xmalloc(sizeof(*badsym));
	badsym->sym = sym;
	badsym->reverted = false;

	list_add_tail(&badsym->list, &mdi->bad_syms);
	return true;
}

void mcount_handle_dlopen(struct symtabs *symtabs, struct dl_phdr_info *info,
			  char *mod_realpath, size_t size)
{
	struct uftrace_mmap *map;
	struct mcount_dynamic_info *mdi;
	char *modname;
	unsigned long vaddr = 0, text_addr = 0;
	unsigned int text_size = 0, namelen, i;
	bool text_section_found = false;

	modname = basename(mod_realpath);

	if (!find_module_list(modname))
		return;

	namelen = strlen(modname) + 1;
	map = xzalloc(sizeof(*map) + namelen);
	map->start = info->dlpi_addr;
	map->len = namelen;
	mcount_memcpy1(map->libname, modname, namelen);

	/* find last section and text section address */
	for (i = 0; i < info->dlpi_phnum; i++) {
		if (info->dlpi_phdr[i].p_type != PT_LOAD)
			continue;

		vaddr = ALIGN(info->dlpi_phdr[i].p_vaddr, 0x1000);
		if (map->end < vaddr)
			map->end = vaddr;

		if ((info->dlpi_phdr[i].p_flags & PF_X) &&
		     !text_section_found) {
			/* find address and size of code segment */
			text_addr = info->dlpi_phdr[i].p_vaddr;
			text_size = info->dlpi_phdr[i].p_memsz;
			text_section_found = true;
		}
	}

	map->end += map->start;
	text_addr += map->start;
	map->mod = load_module_symtab(symtabs, mod_realpath);
	append_map(symtabs->maps, map);

	mdi = create_mdi(map->start, text_addr, text_size);
	mdi->map = map;
	mcount_arch_find_module(mdi, &map->mod->symtab);

	mdi->next = mdinfo;
	mdinfo = mdi;
	if (mcount_setup_trampoline(mdi) < 0) {
		free(mdi);
		pr_dbg("setup trampoline to %s failed", mdi->map->libname);
		free(mdi);
		return;
	}

	patch_func_matched(mdi, map);
}

#ifdef UNIT_TEST
TEST_CASE(dynamic_find_code)
{
	struct mcount_disasm_info info1 = {
		.addr = 0x1000,
		.insns = { 0xaa, 0xbb, 0xcc, 0xdd, },
		.orig_size = 4,
		.copy_size = 4,
	};
	struct mcount_disasm_info info2 = {
		.addr = 0x2000,
		.insns = { 0xf1, 0xf2, 0xcc, 0xdd, },
		.orig_size = 2,
		.copy_size = 4,
	};
	uint8_t jmp_insn[] = { 0xcc };
	uint8_t *insn;

	pr_dbg("create hash map to search code\n");
	code_hmap = hashmap_create(4, hashmap_ptr_hash, hashmap_ptr_equals);

	pr_dbg("save fake code to the hash\n");
	mcount_save_code(&info1, jmp_insn, sizeof(jmp_insn));
	mcount_save_code(&info2, jmp_insn, sizeof(jmp_insn));

	pr_dbg("freeze the code page\n");
	mcount_freeze_code();

	pr_dbg("finding the first code\n");
	insn = mcount_find_code(info1.addr);
	TEST_NE(insn, NULL);
	TEST_MEMEQ(insn, info1.insns, info1.orig_size);

	pr_dbg("finding the second code\n");
	insn = mcount_find_code(info2.addr);
	TEST_NE(insn, NULL);
	TEST_MEMEQ(insn, info2.insns, info2.orig_size);

	pr_dbg("release the code page and hash\n");
	mcount_release_code();
	return TEST_OK;
}

#endif  /* UNIT_TEST */
