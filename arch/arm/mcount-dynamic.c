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
		0x58000050,     /* LDR  ip0, addr */
		0xd61f0200,     /* BR   ip0 */
#else
		0xe59fc000,	/* LDR  ip, addr */
		0xe12fff1c,	/* BX   ip */
#endif
		info->addr + 8,
		(info->addr + 8) >> 32,
	};
	size_t jmp_insn_size = 16;

	if (info->modified) {
		memcpy(&jmp_insn[4], &info->insns[24], 8);
		jmp_insn_size += 8;
	}

	orig = mcount_save_code(info, jmp_insn, jmp_insn_size);

	/* make sure orig->addr same as when called from __dentry__ */
	orig->addr += CODE_SIZE;
}

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	uintptr_t dentry_addr = (uintptr_t)(void *)&__dentry__;
	uint32_t trampoline[] = {
		0xe1a0b00d,	/* MOV  fp, sp */
		0xe59fc000,	/* LDR  ip, &__dentry__  # ldr ip, [pc, #0] */
		0xe12fff1c,	/* BX   ip */
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
	//return (mdi->trampoline - addr - 4) >> 2;
	return (mdi->trampoline - addr - 12) >> 2;
}

#if 0
00010560 <a>:
   10560:       e92d4800        push    {fp, lr}
   10564:       e28db004        add     fp, sp, #4
   10568:       e52de004        push    {lr}            ; (str lr, [sp, #-4]!)
   1056c:       ebffff9a        bl      103dc <__gnu_mcount_nc@plt>
   10570:       eb000003        bl      10584 <b>
   10574:       e1a03000        mov     r3, r0
   10578:       e2433001        sub     r3, r3, #1
   1057c:       e1a00003        mov     r0, r3
   10580:       e8bd8800        pop     {fp, pc}

00010584 <b>:
   10584:       e92d4800        push    {fp, lr}
   10588:       e28db004        add     fp, sp, #4
   1058c:       e52de004        push    {lr}            ; (str lr, [sp, #-4]!)
   10590:       ebffff91        bl      103dc <__gnu_mcount_nc@plt>
   10594:       eb000003        bl      105a8 <c>
   10598:       e1a03000        mov     r3, r0
   1059c:       e2833001        add     r3, r3, #1
   105a0:       e1a00003        mov     r0, r3
   105a4:       e8bd8800        pop     {fp, pc}

000105a8 <c>:
   105a8:       e92d4800        push    {fp, lr}
   105ac:       e28db004        add     fp, sp, #4
   105b0:       e52de004        push    {lr}            ; (str lr, [sp, #-4]!)
   105b4:       ebffff88        bl      103dc <__gnu_mcount_nc@plt>
   105b8:       ebffff7e        bl      103b8 <getpid@plt>
   105bc:       e1a02000        mov     r2, r0
#endif
int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
		      struct mcount_disasm_engine *disasm, unsigned min_size)
{
	//uint32_t push = 0xa9bf7bfd;  /* STP  x29, x30, [sp, #-0x10]! */
	uint32_t push_lr = 0xe52de004;	/* push {lr} */
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
fprintf(stderr, "call patch(%#x) <- %#lx\n", call);

	/* hopefully we're not patching 'memcpy' itself */
	memcpy(insn, &push_lr, sizeof(push_lr));
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
