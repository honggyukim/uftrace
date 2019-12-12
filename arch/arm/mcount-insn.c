#include "libmcount/internal.h"
#include "mcount-arch.h"

#define INSN_SIZE  8

#ifdef HAVE_LIBCAPSTONE
#include <capstone/capstone.h>
#include <capstone/platform.h>

void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
	if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &disasm->engine) != CS_ERR_OK) {
		pr_dbg("failed to init Capstone disasm engine\n");
		return;
	}

	if (cs_option(disasm->engine, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		pr_dbg("failed to set detail option\n");
}

void mcount_disasm_finish(struct mcount_disasm_engine *disasm)
{
	cs_close(&disasm->engine);
}

/* check whether the given instruction is a Thumb32 instruction */
static bool is_thumb32(unsigned long given)
{
	if ((given & 0xf800) == 0xf800 ||
	    (given & 0xf800) == 0xf000 ||
	    (given & 0xf800) == 0xe800)
		return true;
	return false;
}

/* return 0 if it's ok, -1 if not supported, 1 if modifiable */
static int check_prologue(struct mcount_disasm_engine *disasm, cs_insn *insn,
			  bool is_thumb)
{
	int i;
	cs_arm *arm;
	cs_detail *detail;
	bool branch = false;
	int status = -1;

fprintf(stderr, "is_thumb = %d, insn->id = %d\n", is_thumb, insn->id);
//	if (is_thumb) return 0;

	/*
	 * 'detail' can be NULL on "data" instruction
	 * if SKIPDATA option is turned ON
	 */
	if (insn->detail == NULL)
		return -1;

	/* try to fix some PC-relative instructions */
	if (insn->id == ARM_INS_ADR)
		return 1;

#if 0
# FIXME: These must be excluded!

00034110 <start_pager>:
   34110:	e59f3084 	ldr	r3, [pc, #132]	; 3419c <start_pager+0x8c>
   34114:	e92d4010 	push	{r4, lr}
   34118:	e1a0e000 	mov	lr, r0
   3411c:	e893000f 	ldm	r3, {r0, r1, r2, r3}

00038280 <setup_field>:
   38280:	e92d4ff0 	push	{r4, r5, r6, r7, r8, r9, sl, fp, lr}
   38284:	e3a0c000 	mov	ip, #0
   38288:	e5914034 	ldr	r4, [r1, #52]	; 0x34
   3828c:	e24dd01c 	sub	sp, sp, #28

000482b4 <find_symtabs>:
   482b4:	e1a0c000 	mov	ip, r0
   482b8:	e1c001d0 	ldrd	r0, [r0, #16]
   482bc:	e92d4ff8 	push	{r3, r4, r5, r6, r7, r8, r9, sl, fp, lr}
   482c0:	e1510003 	cmp	r1, r3

0002b848 <task_find_sym>:
   2b848:	e1d2c0bc 	ldrh	ip, [r2, #12]
   2b84c:	e92d41f0 	push	{r4, r5, r6, r7, r8, lr}
   2b850:	e1a04002 	mov	r4, r2
   2b854:	e1d260ba 	ldrh	r6, [r2, #10]

0002bac8 <setup_pager>:
   2bac8:       e92d4010        push    {r4, lr}
   2bacc:       e59f0084        ldr     r0, [pc, #132]  ; 2bb58 <setup_pager+0x90>
   2bad0:       ebff9f90        bl      13918 <getenv@plt>
   2bad4:       e1a04000        mov     r4, r0


000141ac <parse_option>:
   141ac:	f240 1339 	movw	r3, #313	; 0x139
   141b0`:	4298      	cmp	r0, r3
   141b2:	e92d 47f0 	stmdb	sp!, {r4, r5, r6, r7, r8, r9, sl, lr}
   141b6:	b082      	sub	sp, #8
   141b8:	69d7      	ldr	r7, [r2, #28]
#endif
#if 0
	if (insn->id == ARM_INS_LDR && (insn->bytes[3] & 0x3b) == 0x18)
		return -1;
#else
	// https://static.docs.arm.com/ddi0406/c/DDI0406C_C_arm_architecture_reference_manual.pdf
	/* check if the instruction is LDR, and it uses PC register */
	if (insn->id == ARM_INS_LDR &&
		 ((insn->bytes[2] & 0xf) == 0xf ||
		  (insn->bytes[1] & 0xf0) == 0xf0))
		return -1;
#endif

	detail = insn->detail;

	for (i = 0; i < detail->groups_count; i++) {
		// BL instruction uses PC for return address */
		switch (detail->groups[i]) {
		case CS_GRP_JUMP:
			branch = true;
			break;
		case CS_GRP_CALL:
		case CS_GRP_RET:
		case CS_GRP_IRET:
#if CS_API_MAJOR >= 4
		case CS_GRP_BRANCH_RELATIVE:
#endif
			return -1;
		default:
			break;
		}

	}

	arm = &insn->detail->arm;

	if (!arm->op_count)
		return 0;

	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &arm->operands[i];
//pr_out("  [%d] instruction: %s\t %s\n", state, insn[i].mnemonic, insn[i].op_str);

		switch (op->type) {
		case ARM_OP_REG:
			status = 0;
			break;
		case ARM_OP_IMM:
			if (branch)
				return -1;
			status = 0;
			break;
		case ARM_OP_MEM:
			status = 0;
			break;
		default:
			break;
		}
	}
	return status;
}

/* return true if it's ok for dynamic tracing */
static bool check_body(struct mcount_disasm_engine *disasm,
		       cs_insn *insn, struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	int i;
	cs_arm *arm;
	cs_detail *detail = insn->detail;
	unsigned long target;
	bool jump = false;

	/* we cannot investigate, not supported */
	if (detail == NULL)
		return false;

	detail = insn->detail;

	/* assume there's no call into the middle of function */
	for (i = 0; i < detail->groups_count; i++) {
		if (detail->groups[i] == CS_GRP_JUMP)
			jump = true;
	}

	if (!jump)
		return true;

	arm = &insn->detail->arm;
	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &arm->operands[i];

		switch (op->type) {
		case ARM_OP_IMM:
			/* capstone seems already calculate target address */
			target = op->imm;

			/* disallow (back) jump to the prologue */
			if (info->addr < target &&
			    target < info->addr + info->copy_size)
				return false;

			/* disallow jump to middle of other function */
			if (info->addr > target ||
			    target >= info->addr + info->sym->size) {
				/* also mark the target function as invalid */
				return !mcount_add_badsym(mdi, insn->address,
							  target);
			}
			break;
		case ARM_OP_MEM:
			/* indirect jumps are not allowed */
			return false;
		case ARM_OP_REG:
			/*
			 * WARN: it should be disallowed too, but many of functions
			 * use branch with register so this would drop the success
			 * rate significantly.  Allowing it for now.
			 */
			return true;
		default:
			break;
		}
	}

	return true;
}

static int opnd_reg(int capstone_reg)
{
	const uint8_t arm_regs[] = {
		ARM_REG_R0,  ARM_REG_R1,  ARM_REG_R2,  ARM_REG_R3,
		ARM_REG_R4,  ARM_REG_R5,  ARM_REG_R6,  ARM_REG_R7,
		ARM_REG_R8,  ARM_REG_R9,  ARM_REG_R10, ARM_REG_R11,
		ARM_REG_R12, ARM_REG_APSR_NZCV,
	};
	size_t i;

	for (i = 0; i < sizeof(arm_regs); i++) {
		if (capstone_reg == arm_regs[i])
			return i;
	}
	return -1;
}

#define REG_SHIFT  5

static bool modify_instruction(struct mcount_disasm_engine *disasm,
			       cs_insn *insn, struct mcount_dynamic_info *mdi,
			       struct mcount_disasm_info *info)
{
	if (insn->id == ARM_INS_ADR) {
		uint32_t ldr_insn = 0x580000c0;
		uint64_t target_addr;
		cs_arm_op *op1 = &insn->detail->arm.operands[0];
		cs_arm_op *op2 = &insn->detail->arm.operands[1];

		/* handle the first ADRP instruction only (for simplicity) */
		if (info->copy_size != 0)
			return false;

		if (op1->type != ARM_OP_REG || op2->type != ARM_OP_IMM)
			return false;

		/*
		 * craft LDR instruction to load addr to op1->reg.
		 * the actual 'addr' is located after 24 byte from the insn.
		 */
		ldr_insn += opnd_reg(op1->reg);
		target_addr = op2->imm;

		memcpy(info->insns, &ldr_insn, sizeof(ldr_insn));
		/* 24 = 8 (orig_insn) + 16 (br insn + address) */
		memcpy(info->insns + 24, &target_addr, sizeof(target_addr));

		info->copy_size += sizeof(ldr_insn);
		info->modified = true;
		return true;
	}

	return false;
}

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	cs_insn *insn = NULL;
	uint32_t count, i;
	int ret = INSTRUMENT_FAILED;
	struct dynamic_bad_symbol *badsym;
	bool is_thumb = info->addr & 1;
	unsigned long addr = info->addr & ~1;

	badsym = mcount_find_badsym(mdi, info->addr);
	if (badsym != NULL) {
		badsym->reverted = true;
		return INSTRUMENT_FAILED;
	}

#if 0
00024158 <command_replay>:
   24158:       f248 6334       movw    r3, #34356      ; 0x8634
   2415c:       f2c0 0306       movt    r3, #6
#endif
	/* detect and set the capstone engine in ARM or THUMB mode */
	if (is_thumb)
		cs_option(disasm->engine, CS_OPT_MODE, CS_MODE_THUMB);
	else
		cs_option(disasm->engine, CS_OPT_MODE, CS_MODE_ARM);

	//count = cs_disasm(disasm->engine, (void *)(info->addr & ~1), info->sym->size,
	count = cs_disasm(disasm->engine, (void *)addr, info->sym->size,
			  addr, 0, &insn);
pr_out("count = %d, info->addr = %#lx\n", count, info->addr);

	for (i = 0; i < count; i++) {
		int state = check_prologue(disasm, &insn[i], is_thumb);
//pr_out("-----------\n");
pr_out("--- state = %d\n", state);
#if 1
		pr_out("  [%d] instruction: %s\t %s\n", state, insn[i].mnemonic, insn[i].op_str);
#else
		pr_out("  [%d] instruction: %s\t %s  -- %s\n", state,
			insn[i].mnemonic, insn[i].op_str,
			cs_group_name(disasm->engine, insn[i].detail->groups[0]));
#endif

		if (state < 0) {
			pr_dbg3("instruction not supported: %s\t %s\n",
				insn[i].mnemonic, insn[i].op_str);
			goto out;
		}

		if (state) {
fprintf(stderr, "> call modify_instruction\n");
			if (!modify_instruction(disasm, &insn[i], mdi, info))
				goto out;
		}
		else {
fprintf(stderr, "    memcpy info->copy_size(%d) -- insn[i].size(%d)\n", info->copy_size, insn[i].size);
			memcpy(info->insns + info->copy_size, insn[i].bytes, insn[i].size);
			info->copy_size += insn[i].size;
		}
		info->orig_size += insn[i].size;

		if (info->orig_size >= INSN_SIZE) {
			ret = INSTRUMENT_SUCCESS;
			break;
		}
	}
return 0;

	while (++i < count) {
		if (!check_body(disasm, &insn[i], mdi, info)) {
			ret = INSTRUMENT_FAILED;
			break;
		}
	}

out:
	if (count)
		cs_free(insn, count);

	return ret;
}

#else /* HAVE_LIBCAPSTONE */

static bool disasm_check_insn(uint8_t *insn)
{
	// LDR (literal)
	if ((*insn & 0x3b) == 0x18)
		return false;

	// ADR or ADRP
	if ((*insn & 0x1f) == 0x10)
		return false;

	// Branch & system instructions
	if ((*insn & 0x1c) == 0x14)
		return false;

	return true;
}

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	uint8_t *insn = (void *)info->addr;
fprintf(stderr, "info->addr(%#lx)\n", info->addr);

	if (!disasm_check_insn(&insn[3]) || !disasm_check_insn(&insn[7]))
		return INSTRUMENT_FAILED;

	//if (insn[

	memcpy(info->insns, insn, INSN_SIZE);
	info->orig_size = INSN_SIZE;
	info->copy_size = INSN_SIZE;

	return INSTRUMENT_SUCCESS;
}

#endif /* HAVE_LIBCAPSTONE */
