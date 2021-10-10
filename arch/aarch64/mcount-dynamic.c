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

/* target instrumentation function it needs to call */
extern void __dentry__(void);
extern void __fentry__(void);

#if 1
enum mcount_aarch64_dynamic_type {
	DYNAMIC_NONE,
	DYNAMIC_PG,
	DYNAMIC_FPATCHABLE,
};

static const char *adi_type_names[] = {
	"none", "pg", "fpatchable",
};

struct arch_dynamic_info {
	enum mcount_aarch64_dynamic_type	type;
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
#if 1
	unsigned long fentry_addr = (unsigned long)__fentry__;
#endif
	/*
	 * trampoline assumes {x29,x30} was pushed but x29 was not updated.
	 * make sure stack is 8-byte aligned.
	 */
	uint32_t trampoline[] = {
		0x910003fd,                     /* MOV  x29, sp */
		0x58000050,                     /* LDR  ip0, &__dentry__ */
		0xd61f0200,                     /* BR   ip0 */
#if 0
		dentry_addr,
		dentry_addr >> 32,
#else
		fentry_addr,
		fentry_addr >> 32,
#endif
	};

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
void mcount_arch_find_module(struct mcount_dynamic_info *mdi,
			     struct symtab *symtab)
{
#if 1
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	struct arch_dynamic_info *adi;
	unsigned int fpatchable_nop_patt[] = { 0xd503201f, 0xd503201f };
	unsigned i = 0;

	adi = xzalloc(sizeof(*adi));  /* DYNAMIC_NONE */

	if (elf_init(mdi->map->libname, &elf) < 0)
		goto out;

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
			adi->type = DYNAMIC_FPATCHABLE;
			goto out;
		}
	}
#else
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	struct arch_dynamic_info *adi;
	unsigned char fentry_nop_patt1[] = { 0x67, 0x0f, 0x1f, 0x04, 0x00 };
	unsigned char fentry_nop_patt2[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char fpatchable_nop_patt[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
	unsigned i = 0;

	adi = xzalloc(sizeof(*adi));  /* DYNAMIC_NONE */

	if (elf_init(mdi->map->libname, &elf) < 0)
		goto out;

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
		if (!memcmp(code_addr, fentry_nop_patt1, CALL_INSN_SIZE) ||
		    !memcmp(code_addr, fentry_nop_patt2, CALL_INSN_SIZE) ||
		    !memcmp(code_addr, fpatchable_nop_patt, CALL_INSN_SIZE)) {
			adi->type = DYNAMIC_FPATCHABLE;
			goto out;
		}
	}
#endif
	switch (check_trace_functions(mdi->map->libname)) {
	case TRACE_MCOUNT:
		adi->type = DYNAMIC_PG;
		break;

	case TRACE_FENTRY:
		adi->type = DYNAMIC_FPATCHABLE;
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
#endif

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi,
				     unsigned long addr)
{
	return (mdi->trampoline - addr - 4) >> 2;
}

#if 0
static int patch_fentry_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	unsigned char nop1[] = { 0x67, 0x0f, 0x1f, 0x04, 0x00 };
	unsigned char nop2[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char nop3[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
	unsigned char *insn = (void *)sym->addr + mdi->map->start;
	unsigned int target_addr;

	/* only support calls to __fentry__ at the beginning */
	if (memcmp(insn, nop1, sizeof(nop1)) &&  /* old pattern */
	    memcmp(insn, nop2, sizeof(nop2)) &&  /* new pattern */
	    memcmp(insn, nop3, sizeof(nop3))) {  /* new pattern */
		pr_dbg("skip non-applicable functions: %s\n", sym->name);
		return INSTRUMENT_FAILED;
	}

	/* get the jump offset to the trampoline */
	target_addr = get_target_addr(mdi, (unsigned long)insn);
	if (target_addr == 0)
		return INSTRUMENT_SKIPPED;

	/* make a "call" insn with 4-byte offset */
	insn[0] = 0xe8;
	/* hopefully we're not patching 'memcpy' itself */
	memcpy(&insn[1], &target_addr, sizeof(target_addr));

	pr_dbg3("update function '%s' dynamically to call __fentry__\n",
		sym->name);

	return INSTRUMENT_SUCCESS;
}
#else
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
//	if (call == 0)
//		return INSTRUMENT_SKIPPED;
#if 0
	/* make a "call" insn with 4-byte offset */
	insn[0] = 0xe8;
	/* hopefully we're not patching 'memcpy' itself */
	memcpy(&insn[1], &target_addr, sizeof(target_addr));
#else
	pr_dbg("target_addr = %#lx\n", call);

	if ((call & 0xfc000000) != 0)
		return INSTRUMENT_FAILED;
#endif

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
#endif

#if 1
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
#if 1
	pr_dbg("target_addr = %#lx\n", call);
#endif

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
#if 1
	struct arch_dynamic_info *adi = mdi->arch;
	int result = INSTRUMENT_SKIPPED;

	if (min_size < CODE_SIZE)
		min_size = CODE_SIZE;

	if (sym->size <= min_size)
		return result;

	switch (adi->type) {
	case DYNAMIC_FPATCHABLE:
		result = patch_fpatchable_func(mdi, sym);
		break;

	case DYNAMIC_NONE:
		result = patch_normal_func(mdi, sym, disasm);
		break;

	default:
		break;
	}
	return result;
#else
	uint32_t push = 0xa9bf7bfd;  /* STP  x29, x30, [sp, #-0x10]! */
	uint32_t call;
	struct mcount_disasm_info info = {
		.sym = sym,
		.addr = sym->addr + mdi->map->start,
	};
	void *insn = (void *)info.addr;

	if (min_size < CODE_SIZE)
		min_size = CODE_SIZE;
	if (sym->size <= min_size)
		return INSTRUMENT_SKIPPED;

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
	memcpy(insn+4, &call, sizeof(call));

	/* flush icache so that cpu can execute the new code */
	__builtin___clear_cache(insn, insn + CODE_SIZE);

	return INSTRUMENT_SUCCESS;
#endif
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
