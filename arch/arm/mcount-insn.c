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

/* return 0 if it's ok, -1 if not supported, 1 if modifiable */
static int check_prologue(struct mcount_disasm_engine *disasm, cs_insn *insn)
{
	int i;
	cs_arm *arm;
	cs_detail *detail;
	bool branch = false;
	int status = -1;

	/*
	 * 'detail' can be NULL on "data" instruction
	 * if SKIPDATA option is turned ON
	 */
	if (insn->detail == NULL)
		return -1;

	/* check if the instruction is LDR, and it uses PC register */
	if (insn->id == ARM_INS_LDR &&
		((insn->bytes[2] & 0xf) == 0xf ||
		 (insn->bytes[1] & 0xf0) == 0xf0)) {
		return -1;
	}

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

	/* detect and set the capstone engine in ARM or THUMB mode */
	if (is_thumb)
		cs_option(disasm->engine, CS_OPT_MODE, CS_MODE_THUMB);
	else
		cs_option(disasm->engine, CS_OPT_MODE, CS_MODE_ARM);

#if 0
	count = cs_disasm(disasm->engine, (void *)info->addr, info->sym->size,
			  info->addr, 0, &insn);
#else
	count = cs_disasm(disasm->engine, (void *)addr, info->sym->size, addr,
			  0, &insn);
#endif

	for (i = 0; i < count; i++) {
fprintf(stderr, "[%d] instruction: %s\t %s\n", i, insn[i].mnemonic, insn[i].op_str);
		if (check_prologue(disasm, &insn[i]) < 0) {
			fprintf(stderr, "instruction not supported: %s\t %s\n",
				insn[i].mnemonic, insn[i].op_str);
			goto out;
		}

fprintf(stderr, "insn[%d].size = %d\n", i, insn[i].size);
		memcpy(info->insns + info->copy_size, insn[i].bytes, insn[i].size);
		info->copy_size += insn[i].size;
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
fprintf(stderr, "check_body failed!\n");
			break;
		}
	}

out:
	if (count)
		cs_free(insn, count);

	return ret;
}

#else /* HAVE_LIBCAPSTONE */

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	return INSTRUMENT_FAILED;
}

#endif /* HAVE_LIBCAPSTONE */
