#include <stdlib.h>

#include "libmcount/internal.h"
#include "utils/filter.h"
#include "utils/utils.h"

/* TODO: not implemented yet (Start) */
static int mcount_get_register_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	return 0;
}

static void mcount_get_stack_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	return;
}

static void mcount_get_struct_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	return;
}

void mcount_arch_get_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	return;
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	return;
}

void mcount_save_arch_context(struct mcount_arch_context *ctx)
{
	return;
}

void mcount_restore_arch_context(struct mcount_arch_context *ctx)
{
	return;
}
/* TODO: not implemented yet (End) */
