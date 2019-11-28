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

static void save_orig_code(struct mcount_disasm_info *info)
{
	struct mcount_orig_insn *orig;
	uint32_t jmp_insn[6] = {
#if 0
		0xe59fc000,	/* ldr  ip, addr */
		0xe12fff1c,	/* bx   ip */
#else
		0xe51ff004,	/* ldr  pc, [pc, #-4] */
		//0xe51ff000,	/* ldr  pc, [pc] */
#endif
		info->addr + 8,
		(info->addr + 8) >> 32,
	};
	size_t jmp_insn_size = 12;

	if (info->modified) {
		memcpy(&jmp_insn[3], &info->insns[24], 8);
		jmp_insn_size += 8;
	}

	orig = mcount_save_code(info, jmp_insn, jmp_insn_size);

	/* make sure orig->addr same as when called from __dentry__ */
	orig->addr += CODE_SIZE;
}

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	uintptr_t dentry_addr = (uintptr_t)(void *)&__dentry__;
	/*
	 * trampoline assumes {fp, lr} was pushed but fp(?) was not updated.
	 * make sure stack is 8-byte aligned.
	 */
	uint32_t trampoline[] = {
		0xe1a0b00d,	/* mov  fp, sp */
		0xe59fc000,	/* ldr  ip, &__dentry__  # ldr ip, [pc, #0] */
		0xe12fff1c,	/* bx   ip */
		dentry_addr,
		dentry_addr >> 32,
	};

	/*
	 * BX <label>:
	 *   Branch and Exchange causes a branch to an address and instruction
	 *   set specified by a register.
	 *
	 * +-----------+-----------------------+-----------+-----------+-----------+-----------+-----------+
	 * |31 30 29 28|27 26 25 24 23 22 21 20|19 18 17 16|15 14 13 12|11 10 09 08|07 06 05 04|03 02 01 00|
	 * +-----------+-----------------------+-----------+-----------+-----------+-----------+-----------+
	 * |    cond   | 0  0  0  1  0  0  1  0| 1  1  1  1| 1  1  1  1| 1  1  1  1| 0  0  0  1|     Rm    |
	 * +-----------+-----------------------+-----------+-----------+-----------+-----------+-----------+
	 */

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

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi,
				     unsigned long addr)
{
	return (mdi->trampoline - addr - 12) >> 2;
}

#if 0
000104ac <main>:
   104ac:       e92d4800        push    {fp, lr}
   104b0:       e28db004        add     fp, sp, #4
   104b4:       e24dd010        sub     sp, sp, #16
   104b8:       e50b0010        str     r0, [fp, #-16]
   104bc:       e50b1014        str     r1, [fp, #-20]  ; 0xffffffec
	...

 1│ Dump of assembler code for function main:
 2│    0x000104ac <+0>:     push    {r11, lr}
 3│    0x000104b0 <+4>:     bl      0x10fec
 4│    0x000104b4 <+8>:     sub     sp, sp, #16
 5│    0x000104b8 <+12>:    str     r0, [r11, #-16]
 6│    0x000104bc <+16>:    str     r1, [r11, #-20] ; 0xffffffec
	...
#endif
int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
		      struct mcount_disasm_engine *disasm, unsigned min_size)
{
#if 1
	uint32_t push = 0xe92d4800;	/* push {fp, lr} */
#else
	uint32_t push = 0xe92d5800;	/* push {fp, ip, lr} */
#endif

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

	/*
	 * BL<c> <label>:
	 *   Branch with Link calls a subroutine at a PC-relative address.
	 *
	 * +-----------+-----------+-----------------------------------------------------------------------+
	 * |31 30 29 28|27 26 25 24|23 22 21 20 19 18 17 16 15 14 13 12 11 10 09 08 07 06 05 04 03 02 01 00|
	 * +-----------+-----------+-----------------------------------------------------------------------+
	 * |    cond   | 1  0  1  1|                                 imm24                                 |
	 * +-----------+-----------+-----------------------------------------------------------------------+
	 *
	 * make a "BL" insn with 24-bit offset.
	 */
	if ((call & 0xff000000) != 0)
		return INSTRUMENT_FAILED;

	call |= 0xeb000000;

	/* hopefully we're not patching 'memcpy' itself */
	memcpy(insn, &push, sizeof(push));
	memcpy(insn+4, &call, sizeof(call));

	/* flush icache so that cpu can execute the new code */
	__builtin___clear_cache(insn, insn + CODE_SIZE);

	return INSTRUMENT_SUCCESS;
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
