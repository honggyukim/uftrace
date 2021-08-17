#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"

#define PAGE_SIZE  4096

#define MCOUNTLOC_SECT  "__mcount_loc"

/* target instrumentation function it needs to call */
extern void __fentry__(void);

enum mcount_i386_dynamic_type {
	DYNAMIC_NONE,		/* not supported */
	DYNAMIC_PG,
	DYNAMIC_FENTRY,
	DYNAMIC_FENTRY_NOP,
};

static const char *adi_type_names[] = {
	"none", "pg", "fentry", "fentry-nop",
};

struct arch_dynamic_info {
	enum mcount_i386_dynamic_type	type;
	struct xray_instr_map		*xrmap;
	unsigned long			*mcount_loc;
	unsigned			nr_mcount_loc;
};

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	unsigned char trampoline[] = { 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0xff, 0x60, 0x04 };
	unsigned long fentry_addr = (unsigned long)__fentry__;
	size_t trampoline_size = 16;
	void *trampoline_check;

	/* find unused 16-byte at the end of the code segment */
	mdi->trampoline = ALIGN(mdi->text_addr + mdi->text_size, PAGE_SIZE) - trampoline_size;

	if (unlikely(mdi->trampoline < mdi->text_addr + mdi->text_size)) {
		mdi->trampoline += trampoline_size;
		mdi->text_size += PAGE_SIZE;

		pr_dbg2("adding a page for fentry trampoline at %#lx\n",
			mdi->trampoline);

		trampoline_check = mmap((void *)mdi->trampoline, PAGE_SIZE,
					PROT_READ | PROT_WRITE,
		     			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
					-1, 0);

		if (trampoline_check == MAP_FAILED)
			pr_err("failed to mmap trampoline for setup");
	}

	if (mprotect((void *)mdi->text_addr, mdi->text_size, PROT_READ | PROT_WRITE)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	/* jmpq  *0x2(%rip)     # <fentry_addr> */
	memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
	memcpy((void *)mdi->trampoline + sizeof(trampoline),
	       &fentry_addr, sizeof(fentry_addr));
	return 0;
}

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	if (mprotect((void *)mdi->text_addr, mdi->text_size, PROT_READ | PROT_EXEC))
		pr_err("cannot restore trampoline due to protection");
}

static void read_mcount_loc(struct arch_dynamic_info *adi,
			    struct uftrace_elf_data *elf,
			    struct uftrace_elf_iter *iter,
			    unsigned long offset)
{
	typeof(iter->shdr) *shdr = &iter->shdr;

	adi->nr_mcount_loc = shdr->sh_size / sizeof(long);
	adi->mcount_loc = xmalloc(shdr->sh_size);

	elf_get_secdata(elf, iter);
	elf_read_secdata(elf, iter, 0, adi->mcount_loc, shdr->sh_size);

	/* symbol has relative address, fix it to match each other */
	if (elf->ehdr.e_type == ET_EXEC) {
		unsigned i;

		for (i = 0; i < adi->nr_mcount_loc; i++) {
			adi->mcount_loc[i] -= offset;
		}
	}
}

void mcount_arch_find_module(struct mcount_dynamic_info *mdi,
			     struct symtab *symtab)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	struct arch_dynamic_info *adi;
	unsigned char fentry_nop_patt[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned i = 0;

	adi = xzalloc(sizeof(*adi));  /* DYNAMIC_NONE */

	if (elf_init(mdi->map->libname, &elf) < 0)
		goto out;

	elf_for_each_shdr(&elf, &iter) {
		char *shstr = elf_get_name(&elf, &iter, iter.shdr.sh_name);

		if (!strcmp(shstr, MCOUNTLOC_SECT)) {
			read_mcount_loc(adi, &elf, &iter, mdi->base_addr);
			/* still needs to check pg or fentry */
		}
	}

	/* check first few functions have fentry signature */
	for (i = 0; i < symtab->nr_sym; i++) {
		struct sym *sym = &symtab->sym[i];
		void *code_addr = (unsigned char *)((uintptr_t)(sym->addr + mdi->map->start));

		if (sym->type != ST_LOCAL_FUNC && sym->type != ST_GLOBAL_FUNC)
			continue;

		/* dont' check special functions */
		if (sym->name[0] == '_')
			continue;

		/* only support calls to __fentry__ at the beginning */
		if (!memcmp(code_addr, fentry_nop_patt, CALL_INSN_SIZE)) {
			adi->type = DYNAMIC_FENTRY_NOP;
			goto out;
		}
	}

	switch (check_trace_functions(mdi->map->libname)) {
	case TRACE_MCOUNT:
		adi->type = DYNAMIC_PG;
		break;
	case TRACE_FENTRY:
		adi->type = DYNAMIC_FENTRY;
		break;
	default:
		break;
	}

out:
	pr_dbg("dynamic patch type: %s: %d (%s)\n", basename(mdi->map->libname),
	       adi->type, adi_type_names[adi->type]);

	mdi->arch = adi;
	elf_finish(&elf);
}

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi, unsigned long addr)
{
	while (mdi) {
		if (mdi->text_addr <= addr && addr < mdi->text_addr + mdi->text_size)
			return mdi->trampoline - (addr + CALL_INSN_SIZE);

		mdi = mdi->next;
	}
	return 0;
}

static int patch_fentry_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	// In case of "gcc" which is not patched because of old version, 
	// it may not create 5 byte nop.
	unsigned char nop[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char *insn = (unsigned char *)((uintptr_t)(sym->addr + mdi->map->start));
	unsigned int target_addr;

	/* only support calls to __fentry__ at the beginning */
	if (memcmp(insn, nop, sizeof(nop))) {
		pr_dbg2("skip non-applicable functions: %s\n", sym->name);
		return -2;
	}

	/* get the jump offset to the trampoline */
	target_addr = get_target_addr(mdi, (unsigned long)insn);
	if (target_addr == 0)
		return -2;

	/* make a "call" insn with 4-byte offset */
	insn[0] = 0xe8;
	/* hopefully we're not patching 'memcpy' itself */
	memcpy(&insn[1], &target_addr, sizeof(target_addr));

	pr_dbg3("update function '%s' dynamically to call __fentry__\n",
		sym->name);

	return 0;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
		      struct mcount_disasm_engine *disasm, unsigned min_size)
{
	struct arch_dynamic_info *adi = mdi->arch;
	int result = INSTRUMENT_SKIPPED;

	if (min_size < CALL_INSN_SIZE)
		min_size = CALL_INSN_SIZE;

	if (sym->size < min_size)
		return result;

	switch (adi->type) {
	case DYNAMIC_FENTRY_NOP:
		result = patch_fentry_func(mdi, sym);
		break;
	default:
		break;
	}
	return result;
}

