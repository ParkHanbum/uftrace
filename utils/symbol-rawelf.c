#ifndef HAVE_LIBELF

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "symbol"
#define PR_DOMAIN  DBG_SYMBOL

#include "utils/utils.h"
#include "utils/symbol-rawelf.h"

/*
 *  ELF File Header validation logic.
 */
int elf_validation(struct uftrace_elf_data *elf)
{
	Elf_Ehdr *ehdr;
	int eclass, data, version;
	unsigned long mapped_saddr, addr;
	int res = 0;

	ehdr = &elf->ehdr;

	// validate ELF Magic.
	if (memcmp(ehdr, ELFMAG, SELFMAG)) {
		pr_dbg3("ELF Signature not matched\n");
		// return -1;
	}

	// validate some field of elf header.
	eclass = (int) ehdr->e_ident[EI_CLASS];
	data = (int) ehdr->e_ident[EI_DATA];
	version = (int) ehdr->e_ident[EI_VERSION];

	if (!(eclass > ELFCLASSNONE && eclass < ELFCLASSNUM)) {
		pr_dbg3("Invalid eclass : [%d]\n", eclass);
		// return -1;
	}

	if (!(data > ELFDATANONE && data < ELFDATANUM)) {
		pr_dbg3("Invalid endian : [%d]\n", data);
		// return -1;
	}

	if (!(version > EV_NONE && version < EV_NUM)) {
		pr_dbg3("Invalid ELF version : [%d]\n", version);
		// return -1;
	}

	if (ehdr->e_phnum == 0 || ehdr->e_phentsize == 0) {
		pr_dbg3("Invalid Program header. Num:[%d] Size:[%d]\n",
				ehdr->e_phnum, ehdr->e_phentsize);
		// return -1;
	}

	if (ehdr->e_shnum > 0 && ehdr->e_shentsize == 0) {
		pr_dbg3("Section Header entry size cannot be 0.\n");
		// return -1;
		res = -1;
	}

	// start address the ELF mapped.
	mapped_saddr = (long)elf->file_map;
	addr = mapped_saddr + ehdr->e_phoff +
		ehdr->e_phnum * ehdr->e_phentsize;

	if (addr > mapped_saddr + elf->file_size) {
		pr_dbg3("Invalid Program Header address. "\
				"mapped address : [%llx - %llx]" \
				"but phdr address is : [%llx]\n",
				mapped_saddr,
				mapped_saddr + elf->file_size, addr);
		// return -1;
		res = -1;
	}

	addr = mapped_saddr + ehdr->e_shoff +
		ehdr->e_shnum * ehdr->e_shentsize;

	if (addr > mapped_saddr + elf->file_size) {
		pr_dbg3("Invalid Section Header address. "\
				"mapped address : [%llx - %llx]" \
				"but shdr address is : [%llx]\n",
				mapped_saddr,
				mapped_saddr + elf->file_size, addr);
		elf->have_section = false;
		res = -1;
	}
	else
		elf->have_section = true;

	return res;
}

int elf_init(const char *filename, struct uftrace_elf_data *elf)
{
	struct stat stbuf;

	elf->fd = open(filename, O_RDONLY);
	if (elf->fd < 0)
		return -1;

	if (fstat(elf->fd, &stbuf) < 0)
		goto err;

	elf->file_size = stbuf.st_size;

	elf->file_map = mmap(NULL, elf->file_size, PROT_READ, MAP_PRIVATE,
			     elf->fd, 0);
	if (elf->file_map == MAP_FAILED)
		goto err;

	memcpy(&elf->ehdr, elf->file_map, sizeof(elf->ehdr));

	if (elf_validation(elf) < 0)
		goto err;

	return 0;

err:
	close(elf->fd);
	elf->fd = -1;

	elf->file_map = NULL;
	return -1;
}

void elf_finish(struct uftrace_elf_data *elf)
{
	munmap(elf->file_map, elf->file_size);
	elf->file_map = NULL;

	close(elf->fd);
	elf->fd = -1;
}

void elf_get_strtab(struct uftrace_elf_data *elf,
		    struct uftrace_elf_iter *iter,
		    int shidx)
{
	Elf_Shdr *shdr = elf->file_map + elf->ehdr.e_shoff;

	iter->strtab = elf->file_map + shdr[shidx].sh_offset;
}

void elf_get_secdata(struct uftrace_elf_data *elf,
		     struct uftrace_elf_iter *iter)
{
	if (elf->have_section) {
		iter->ent_size = iter->shdr.sh_entsize;
		iter->data = elf->file_map + iter->shdr.sh_offset;
	}
}

void elf_read_secdata(struct uftrace_elf_data *elf,
		      struct uftrace_elf_iter *iter,
		      unsigned offset, void *buf, size_t len)
{
	memcpy(buf, &iter->data[offset], len);
}

#endif  /* HAVE_LIBELF */
