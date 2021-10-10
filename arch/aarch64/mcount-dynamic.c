#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "mcount-arch.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/rbtree.h"

#define PAGE_SIZE  4096
#define CODE_SIZE  8
#define PATCHABLE_SECT  "__patchable_function_entries"

/* target instrumentation function it needs to call */
extern void __dentry__(void);
extern void __fentry__(void);

#if 1
enum mcount_aarch64_dynamic_type {
	DYNAMIC_NONE,
	DYNAMIC_PG,
	DYNAMIC_PATCHABLE,
};

static const char *adi_type_names[] = {
	"none", "pg", "fpatchable",
};

struct arch_dynamic_info {
	enum mcount_aarch64_dynamic_type	type;
	unsigned long				*patchable_loc;
	unsigned				nr_patchable_loc;
};
#endif

static void save_orig_code(struct mcount_disasm_info *info)
{
	uint32_t jmp_insn[6] = {
		0x58000050,     /* LDR  ip0, addr */
		0xd61f0200,     /* BR   ip0 */
		info->addr + 8,
		(info->addr + 8) >> 32,
	};
	size_t jmp_insn_size = 16;

	if (info->modified) {
		memcpy(&jmp_insn[4], &info->insns[24], 8);
		jmp_insn_size += 8;
	}

	/* make sure info.addr same as when called from __dentry__ */
	mcount_save_code(info, CODE_SIZE, jmp_insn, jmp_insn_size);
}

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	uintptr_t dentry_addr = (uintptr_t)(void *)&__dentry__;
	uintptr_t fentry_addr = (uintptr_t)(void *)&__fentry__;
	struct arch_dynamic_info *adi = mdi->arch;
	/*
	 * trampoline assumes {x29,x30} was pushed but x29 was not updated.
	 * make sure stack is 8-byte aligned.
	 */
	uint32_t trampoline[5] = {
		0x910003fd,                     /* MOV  x29, sp */
		0x58000050,                     /* LDR  ip0, &__dentry__ */
		0xd61f0200,                     /* BR   ip0 */
		dentry_addr,
		dentry_addr >> 32,
	};

	if (adi->type == DYNAMIC_PATCHABLE) {
		trampoline[3] = fentry_addr;
		trampoline[4] = fentry_addr >> 32;
	}

	/* find unused 16-byte at the end of the code segment */
	mdi->trampoline  = ALIGN(mdi->text_addr + mdi->text_size, PAGE_SIZE);
	mdi->trampoline -= sizeof(trampoline);

	if (unlikely(mdi->trampoline < mdi->text_addr + mdi->text_size)) {
		mdi->trampoline += sizeof(trampoline);
		mdi->text_size += PAGE_SIZE;

		pr_dbg("adding a page for fentry trampoline at %#lx\n",
		       mdi->trampoline);

		mmap((void *)mdi->trampoline, PAGE_SIZE,
		     PROT_READ | PROT_WRITE | PROT_EXEC,
		     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}

	if (mprotect((void *)mdi->text_addr, mdi->text_size,
		     PROT_READ | PROT_WRITE | PROT_EXEC)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
	return 0;
}

#if 1
static void read_patchable_loc(struct arch_dynamic_info *adi,
			    struct uftrace_elf_data *elf,
			    struct uftrace_elf_iter *iter,
			    unsigned long offset)
{
	typeof(iter->shdr) *shdr = &iter->shdr;

	adi->nr_patchable_loc = shdr->sh_size / sizeof(long);
	adi->patchable_loc = xmalloc(shdr->sh_size);

	elf_get_secdata(elf, iter);
	elf_read_secdata(elf, iter, 0, adi->patchable_loc, shdr->sh_size);

	/* symbol has relative address, fix it to match each other */
	if (elf->ehdr.e_type == ET_EXEC) {
		unsigned i;

		for (i = 0; i < adi->nr_patchable_loc; i++) {
			adi->patchable_loc[i] -= offset;
			pr_yellow("adi->patchable_loc[%u] = %#lx\n", i, adi->patchable_loc[i]);
		}
	}
}
#endif

void mcount_arch_find_module(struct mcount_dynamic_info *mdi,
			     struct symtab *symtab)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	struct arch_dynamic_info *adi;
	unsigned int fpatchable_nop_patt[] = { 0xd503201f, 0xd503201f };
	unsigned i = 0;

	adi = xzalloc(sizeof(*adi));  /* DYNAMIC_NONE */

	if (elf_init(mdi->map->libname, &elf) < 0)
		goto out;

#if 0
	elf_for_each_shdr(&elf, &iter) {
		char *shstr = elf_get_name(&elf, &iter, iter.shdr.sh_name);

		if (!strcmp(shstr, XRAY_SECT)) {
			adi->type = DYNAMIC_XRAY;
			read_xray_map(adi, &elf, &iter, mdi->base_addr);
			goto out;
		}

		if (!strcmp(shstr, MCOUNTLOC_SECT)) {
			read_mcount_loc(adi, &elf, &iter, mdi->base_addr);
			/* still needs to check pg or fentry */
		}
	}
#else
	elf_for_each_shdr(&elf, &iter) {
		char *shstr = elf_get_name(&elf, &iter, iter.shdr.sh_name);
#if 0
		if (!strcmp(shstr, XRAY_SECT)) {
			adi->type = DYNAMIC_XRAY;
			read_xray_map(adi, &elf, &iter, mdi->base_addr);
			goto out;
		}
#endif
		if (!strcmp(shstr, PATCHABLE_SECT)) {
			adi->type = DYNAMIC_PATCHABLE;
			read_patchable_loc(adi, &elf, &iter, mdi->base_addr);
			goto out;
		}
	}
#endif
	/* check first few functions have fentry signature */
	for (i = 0; i < symtab->nr_sym; i++) {
		struct sym *sym = &symtab->sym[i];
		void *code_addr = (void *)sym->addr + mdi->map->start;

		if (sym->type != ST_LOCAL_FUNC && sym->type != ST_GLOBAL_FUNC)
			continue;

		/* dont' check special functions */
		if (sym->name[0] == '_')
			continue;

		/* only support calls to __fentry__ at the beginning */
		if (!memcmp(code_addr, fpatchable_nop_patt, CODE_SIZE)) {
			adi->type = DYNAMIC_PATCHABLE;
			goto out;
		}
	}

	switch (check_trace_functions(mdi->map->libname)) {
	case TRACE_MCOUNT:
		adi->type = DYNAMIC_PG;
		break;
#if 0
	case TRACE_FENTRY:
		adi->type = DYNAMIC_PATCHABLE;
		break;
#endif
	default:
		break;
	}

out:
	pr_dbg("dynamic patch type: %s: %d (%s)\n", basename(mdi->map->libname),
	       adi->type, adi_type_names[adi->type]);

	mdi->arch = adi;
	elf_finish(&elf);
}

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi,
				     unsigned long addr)
{
	return (mdi->trampoline - addr - 4) >> 2;
}

#if 1
static int patch_fpatchable_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	uint32_t push = 0xa9bf7bfd;  /* STP  x29, x30, [sp, #-0x10]! */
	uint32_t call;
	unsigned int fpatchable_nop_patt[] = { 0xd503201f, 0xd503201f };
	unsigned char *insn = (void *)sym->addr + mdi->map->start;

	/* only support calls to 2 nops at the beginning */
	if (memcmp(insn, fpatchable_nop_patt, sizeof(fpatchable_nop_patt))) {
		pr_dbg("skip non-applicable functions: %s\n", sym->name);
		return INSTRUMENT_FAILED;
	}

	call = get_target_addr(mdi, (unsigned long)insn);

	if ((call & 0xfc000000) != 0)
		return INSTRUMENT_FAILED;

	pr_dbg3("update function '%s' dynamically to call __fentry__\n",
		sym->name);

	/* make a "BL" insn with 26-bit offset */
	call |= 0x94000000;

	/* hopefully we're not patching 'memcpy' itself */
	memcpy(insn, &push, sizeof(push));
	memcpy(insn + 4, &call, sizeof(call));

	/* flush icache so that cpu can execute the new code */
	__builtin___clear_cache(insn, insn + CODE_SIZE);

	return INSTRUMENT_SUCCESS;
}

static int patch_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			     struct mcount_disasm_engine *disasm)
{
	uint32_t push = 0xa9bf7bfd;  /* STP  x29, x30, [sp, #-0x10]! */
	uint32_t call;
	struct mcount_disasm_info info = {
		.sym = sym,
		.addr = sym->addr + mdi->map->start,
	};
	void *insn = (void *)info.addr;

	if (disasm_check_insns(disasm, mdi, &info) < 0)
		return INSTRUMENT_FAILED;

	save_orig_code(&info);

	call = get_target_addr(mdi, info.addr);

	if ((call & 0xfc000000) != 0)
		return INSTRUMENT_FAILED;

	pr_dbg2("force patch normal func: %s (patch size: %d)\n",
		sym->name, info.orig_size);

	/* make a "BL" insn with 26-bit offset */
	call |= 0x94000000;

	/* hopefully we're not patching 'memcpy' itself */
	memcpy(insn, &push, sizeof(push));
	memcpy(insn + 4, &call, sizeof(call));

	/* flush icache so that cpu can execute the new code */
	__builtin___clear_cache(insn, insn + CODE_SIZE);

	return INSTRUMENT_SUCCESS;
}
#endif

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
		      struct mcount_disasm_engine *disasm, unsigned min_size)
{
	struct arch_dynamic_info *adi = mdi->arch;
	int result = INSTRUMENT_SKIPPED;

	if (min_size < CODE_SIZE)
		min_size = CODE_SIZE;

	if (sym->size <= min_size)
		return result;

	switch (adi->type) {
	case DYNAMIC_PATCHABLE:
		result = patch_fpatchable_func(mdi, sym);
		break;

	case DYNAMIC_NONE:
		result = patch_normal_func(mdi, sym, disasm);
		break;

	default:
		break;
	}
	return result;
}

static void revert_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			       struct mcount_disasm_engine *disasm)
{
	void *addr = (void *)(uintptr_t)sym->addr + mdi->map->start;
	void *saved_insn;

	saved_insn = mcount_find_code((uintptr_t)addr + CODE_SIZE);
	if (saved_insn == NULL)
		return;

	memcpy(addr, saved_insn, CODE_SIZE);
	__builtin___clear_cache(addr, addr + CODE_SIZE);
}

void mcount_arch_dynamic_recover(struct mcount_dynamic_info *mdi,
				 struct mcount_disasm_engine *disasm)
{
	struct dynamic_bad_symbol *badsym, *tmp;

	list_for_each_entry_safe(badsym, tmp, &mdi->bad_syms, list) {
		if (!badsym->reverted)
			revert_normal_func(mdi, badsym->sym, disasm);

		list_del(&badsym->list);
		free(badsym);
	}
}
