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

/* check whether the given instruction is a Thumb32 instruction */
static bool is_thumb32(unsigned long given)
{
	if ((given & 0xf800) == 0xf800 ||
	    (given & 0xf800) == 0xf000 ||
	    (given & 0xf800) == 0xe800)
		return true;
	return false;
}

static void save_orig_code(struct mcount_disasm_info *info)
{
	bool is_thumb = info->addr & 1;
	struct mcount_orig_insn *orig;
	uint32_t jmp_insn[6] = {
		/* arm mode */
		0xe51ff004,	/* ldr  pc, [pc, #-4] */
		info->addr + 8,
		(info->addr + 8) >> 32,
	};
	uint32_t jmp_insn_thumb[6] = {
		/* thumb mode */
		0xc004f8df,	/* ldr.w  ip, &__dentry__  # ldr.w ip, [pc, #4] */	// GOOD!
		0x00004760,	/* bx     ip */
		info->addr + 8,
		(info->addr + 8) >> 32,
	};
	uint32_t jmp_insn_thumb2[6] = {
		/* thumb mode */
		0xc004f8df,	/* ldr.w  ip, &__dentry__  # ldr.w ip, [pc, #4] */	// GOOD!
		0x00004760,	/* bx     ip */
		info->addr + 10,
		(info->addr + 10) >> 32,
	};
	size_t jmp_insn_size = 12;
	size_t jmp_insn_thumb_size = 16;
fprintf(stderr, "info->addr + 10 = %lx\n", info->addr + 10);
#if 0
	if (info->modified) {
		memcpy(&jmp_insn[3], &info->insns[24], 8);
		jmp_insn_size += 8;
	}
#endif
#if 0
000141ac <parse_option>:
   141ac:	f240 1339 	movw	r3, #313	; 0x139
   141b0:	4298      	cmp	r0, r3
   141b2:	e92d 47f0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, sl, lr}
   141b6:	b082      	sub	sp, #8
   141b8:	69d7      	ldr	r7, [r2, #28]
#endif
	if (is_thumb == false)
		orig = mcount_save_code(info, jmp_insn, jmp_insn_size);
	else {
		unsigned long addr = info->addr & ~1;
		if (!is_thumb32(*(uint16_t*)(addr + 6)))
			orig = mcount_save_code(info, jmp_insn_thumb, jmp_insn_thumb_size);
		else {
			fprintf(stderr, "thumb32 in addr(%lx)\n", addr);
			fprintf(stderr, "thumb32 in info->addr(%lx)\n", info->addr);
			info->orig_size += 2;
			info->copy_size += 2;
			orig = mcount_save_code(info, jmp_insn_thumb2, jmp_insn_thumb_size);
			orig->addr += 2;
		}
	}

	/* make sure orig->addr same as when called from __dentry__ */
	orig->addr += CODE_SIZE;
}

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
#if 0
   13a96:	f8d3 c000 	ldr.w	ip, [r3]
   1665a:	f8d5 c00a 	ldr.w	ip, [r5, #10]
   16718:	f8d4 c000 	ldr.w	ip, [r4]
   175f0:	f8d4 c014 	ldr.w	ip, [r4, #20]
   17718:	f853 cc08 	ldr.w	ip, [r3, #-8]
   17da0:	f8d3 c02c 	ldr.w	ip, [r3, #44]	; 0x2c
   1c042:	f8d5 c004 	ldr.w	ip, [r5, #4]

   1aa16:	f04f 0b00 	mov.w	fp, #0
   1aa42:	f04f 0b01 	mov.w	fp, #1
   20712:	ea4f 0bcb 	mov.w	fp, fp, lsl #3
   243aa:	f04f 0b28 	mov.w	fp, #40	; 0x28
   27ab4:	ea4f 0b86 	mov.w	fp, r6, lsl #2
   2d30a:	ea4f 0beb 	mov.w	fp, fp, asr #3

   17eae:       4770            bx      lr
   17eb6:       4718            bx      r3

        :	ea4f 0b0d 	mov.w	fp, sp
        :	f8df c000 	ldr.w	ip, [pc, #0]
        :       4760            bx      ip
        :       0000
#endif
	uintptr_t dentry_addr = (uintptr_t)(void *)&__dentry__;
	/*
	 * trampoline assumes {fp, lr} was pushed but fp(?) was not updated.
	 * make sure stack is 8-byte aligned.
	 */
	uint32_t trampoline[10] = {
		/* arm mode */
		0xe1a0b00d,	/* mov  fp, sp */
		0xe59fc000,	/* ldr  ip, &__dentry__  # ldr ip, [pc, #0] */
		0xe12fff1c,	/* bx   ip */
		dentry_addr,
		dentry_addr >> 32,

		/* thumb mode */
		0x0b0dea4f,	/* mov.w  fp, sp */
		0xc004f8df,	/* ldr.w  ip, &__dentry__  # ldr.w ip, [pc, #4] */	// GOOD!
		0x00004760,	/* bx     ip */
		dentry_addr,
		dentry_addr >> 32,
	};
	//uint32_t *trampoline2 = &trampoline[5];

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
#if 0
	mdi->trampoline2  = ALIGN(mdi->text_addr + mdi->text_size, PAGE_SIZE);
	mdi->trampoline2 -= sizeof(trampoline2);
#else
	mdi->trampoline2  = mdi->trampoline + 5 * sizeof(unsigned long);
#endif

	if (unlikely(mdi->trampoline < mdi->text_addr + mdi->text_size)) {
		mdi->trampoline += sizeof(trampoline);
		mdi->text_size += PAGE_SIZE;

		pr_dbg("adding a page for fentry trampoline at %#lx\n",
		       mdi->trampoline);

		mmap((void *)mdi->trampoline, PAGE_SIZE,
		     PROT_READ | PROT_WRITE | PROT_EXEC,
		     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}
#if 0
	if (unlikely(mdi->trampoline2 < mdi->text_addr + mdi->text_size)) {
		mdi->trampoline2 += sizeof(trampoline2);
		mdi->text_size += PAGE_SIZE;

		pr_dbg("adding a page for fentry trampoline2 at %#lx\n",
		       mdi->trampoline2);

		mmap((void *)mdi->trampoline2, PAGE_SIZE,
		     PROT_READ | PROT_WRITE | PROT_EXEC,
		     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}
#endif

	if (mprotect((void *)mdi->text_addr, mdi->text_size,
		     PROT_READ | PROT_WRITE | PROT_EXEC)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
#if 0
	memcpy((void *)mdi->trampoline2, trampoline2, sizeof(trampoline2));
#endif
	return 0;
}

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi,
				     unsigned long addr)
{
	bool is_thumb = addr & 1;
	unsigned long target_addr;

	if (is_thumb == false) {
		target_addr = (mdi->trampoline - addr - 12) >> 2;
	}
	else {
		addr &= ~1;
		/*
		 * BL<c> <label>:
		 *   Branch with Link calls a subroutine at a PC-relative address.
		 *
		 * +--------------+--+-----------------------------++-----+--+--+--+--------------------------------+
		 * |15 14 13 12 11|10|09 08 07 06 05 04 03 02 01 00||15 14|13|12|11|10 09 08 07 06 05 04 03 02 01 00|
		 * +--------------+--+-----------------------------++-----+--+--+--+--------------------------------+
		 * | 1  1  1  1  0| S|            imm10            || 1  1|J1| 1|J2|              imm11             |
		 * +--------------+--+-----------------------------++-----+--+--+--+--------------------------------+
		 *
		 *   I1 = NOT(J1 EOR S);
		 *   I2 = NOT(J2 EOR S);
		 *   imm32 = SignExtend(S:I1:I2:imm10:imm11:'0', 32);
		 *
		 * make a "BL" insn with 24-bit offset.
		 */
		//target_addr = (mdi->trampoline2 - addr - 4) >> 1;
		//target_addr = ((mdi->trampoline2 - addr - 12) >> 1) << 16;
		//target_addr = ((mdi->trampoline2 - addr - 6) >> 1) << 16;
#if 0
   13b34:	f000 f9c2 	bl	13ebc <parse_opt_file>
   13be0:	f020 fb2e 	bl	34240 <setup_color>
   13be4:	f01a fc3c 	bl	2e460 <setup_signal>
   13bf6:	f011 fdc7 	bl	25788 <start_pager>
   13c0c:	f000 f9fa 	bl	14004 <apply_default_opts>
   13c6e:	f011 fd55 	bl	2571c <setup_pager>
   13c7c:	f00c fe82 	bl	20984 <command_graph>
   13c82:	f011 fd2b 	bl	256dc <wait_for_pager>
   13c9c:	f01b fa5c 	bl	2f158 <free_parsed_cmdline>
		call |= 0xf800f000;
#endif
#if 0
		target_addr = ((mdi->trampoline2 - addr - 8) >> 1) << 16;
#else
		unsigned long imm32 = (mdi->trampoline2 - addr - 8) >> 1;
		unsigned long imm10 = (imm32 & (0x3ff << 11)) >> 11;
		unsigned long imm11 = (imm32 & 0x7ff) << 16;
		target_addr = imm11 | imm10;
#endif
		//target_addr = (mdi->trampoline2 - addr - 12) >> 1;
		//unsigned long imm32
#if 0
imm32 = SignExtend(S:I1:I2:imm10:imm11:'0', 32);
>>> hex(0x10448 + (4 + 2) * 2)
'0x10454'
>>> hex(0x10448 + ((4 + 2) << 1))
'0x10454'
#endif
#if 0
   13b34:	f000 f9c2 	bl	13ebc <parse_opt_file>
   13be0:	f020 fb2e 	bl	34240 <setup_color>
   13be4:	f01a fc3c 	bl	2e460 <setup_signal>
   13bf6:	f011 fdc7 	bl	25788 <start_pager>
   13c0c:	f000 f9fa 	bl	14004 <apply_default_opts>
   13c6e:	f011 fd55 	bl	2571c <setup_pager>
   13c7c:	f00c fe82 	bl	20984 <command_graph>
   13c82:	f011 fd2b 	bl	256dc <wait_for_pager>
   13c9c:	f01b fa5c 	bl	2f158 <free_parsed_cmdline>
#endif
#if 0
00003a60: 2de9 f043 cbb0 0cad 0446 0f46 0390 0291  -..C.....F.F....

00013a60 <main>:
   13a60:	e92d 43f0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, lr}
   13a64:	b0cb      	sub	sp, #300	; 0x12c
   13a66:	ad0c      	add	r5, sp, #48	; 0x30
   13a68:	4604      	mov	r4, r0
   13a6a:	460f      	mov	r7, r1
   13a6c:	9003      	str	r0, [sp, #12]
   13a6e:	9102      	str	r1, [sp, #8]

00003a70: f822 0021 2846 47f2 b009 c0f2 0609 fff7  .".!(FG.........

   13a70:	22f8      	movs	r2, #248	; 0xf8
   13a72:	2100      	movs	r1, #0
   13a74:	4628      	mov	r0, r5
   13a76:	f247 09b0 	movw	r9, #28848	; 0x70b0
   13a7a:	f2c0 0906 	movt	r9, #6
   13a7e:	f7ff ebec 	blx	13258 <memset@plt>
#endif
	}
	return target_addr;
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
#if 0
00024158 <command_replay>:
   24158:       f248 6334       movw    r3, #34356      ; 0x8634
   2415c:       f2c0 0306       movt    r3, #6
   24160:       e92d 4ff0       stmdb   sp!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}
   24164:       2102            movs    r1, #2
...
00024f0c <delete_session_map>:
   24f0c:       b538            push    {r3, r4, r5, lr}
   24f0e:       4605            mov     r5, r0
   24f10:       69c0            ldr     r0, [r0, #28]
...
00024f28 <create_session>:
   24f28:       e92d 4ff0       stmdb   sp!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}
   24f2c:       b089            sub     sp, #36 ; 0x24
   24f2e:       4680            mov     r8, r0
...
#endif
#if 1
	bool is_thumb = sym->addr & 1;
	uint32_t push = 0xe92d4800;	/* push {fp, lr} */
	//uint16_t push2 = 0xb700;	/* wrong: thumb: push {fp, lr} */
	//uint16_t push2 = 0xb500;	/* thumb: push {lr} */
	uint32_t push2 = 0x4800e92d;	/* thumb: push.w {fp, lr} */
#else
	uint32_t push = 0xe92d5800;	/* push {fp, ip, lr} */
#endif

	uint32_t call;
	struct mcount_disasm_info info = {
		.sym = sym,
		.addr = sym->addr + mdi->map->start,
	};
	void *insn = (void *)(info.addr & ~1);

	if (min_size < CODE_SIZE)
		min_size = CODE_SIZE;
	if (sym->size <= min_size)
		return INSTRUMENT_SKIPPED;

	if (disasm_check_insns(disasm, mdi, &info) < 0)
		return INSTRUMENT_FAILED;

	save_orig_code(&info);

	call = get_target_addr(mdi, info.addr);

	if (is_thumb == false) {
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
	}
	else {
		/*
		 * BL<c> <label>:
		 *   Branch with Link calls a subroutine at a PC-relative address.
		 *
		 * +--------------+--+-----------------------------++-----+--+--+--+--------------------------------+
		 * |15 14 13 12 11|10|09 08 07 06 05 04 03 02 01 00||15 14|13|12|11|10 09 08 07 06 05 04 03 02 01 00|
		 * +--------------+--+-----------------------------++-----+--+--+--+--------------------------------+
		 * | 1  1  1  1  0| S|            imm10            || 1  1|J1| 1|J2|              imm11             |
		 * +--------------+--+-----------------------------++-----+--+--+--+--------------------------------+
		 *
		 *   I1 = NOT(J1 EOR S);
		 *   I2 = NOT(J2 EOR S);
		 *   imm32 = SignExtend(S:I1:I2:imm10:imm11:'0', 32);
		 *
		 * make a "BL" insn with 24-bit offset.
		 */
//		if ((call & 0xff000000) != 0)
//			return INSTRUMENT_FAILED;

#if 0
imm32 = SignExtend(S:I1:I2:imm10:imm11:'0', 32);
>>> hex(0x10448 + (4 + 2) * 2)
'0x10454'
>>> hex(0x10448 + ((4 + 2) << 1))
'0x10454'
#endif
		call |= 0xf800f000;
#if 0
   13b34:	f000 f9c2 	bl	13ebc <parse_opt_file>

   13be0:	f020 fb2e 	bl	34240 <setup_color>
=> 2efb20f0

   13be4:	f01a fc3c 	bl	2e460 <setup_signal>
   13bf6:	f011 fdc7 	bl	25788 <start_pager>
   13c0c:	f000 f9fa 	bl	14004 <apply_default_opts>
   13c6e:	f011 fd55 	bl	2571c <setup_pager>
   13c7c:	f00c fe82 	bl	20984 <command_graph>
   13c82:	f011 fd2b 	bl	256dc <wait_for_pager>
   13c9c:	f01b fa5c 	bl	2f158 <free_parsed_cmdline>
#endif
   		unsigned long addr_6 = (unsigned long)insn + 6;

		/* hopefully we're not patching 'memcpy' itself */
		memcpy(insn, &push2, sizeof(push2));
		if (is_thumb32(*(uint16_t*)addr_6)) {
			uint16_t nop = 0xbf00;
			memcpy(insn+4, &nop, sizeof(nop));
			memcpy(insn+6, &call, sizeof(call));
			/* flush icache so that cpu can execute the new code */
			__builtin___clear_cache(insn, insn + CODE_SIZE + 2);
		}
		else {
			memcpy(insn+4, &call, sizeof(call));
			/* flush icache so that cpu can execute the new code */
			__builtin___clear_cache(insn, insn + CODE_SIZE);
		}
	}

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
