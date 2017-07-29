/*
 * Script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#ifndef __UFTRACE_SCRIPT_H__
#define __UFTRACE_SCRIPT_H__

#include "libmcount/mcount.h"
#include "utils/script-python.h"

/* script type */
enum script_type_t {
	SCRIPT_UNKNOWN = 0,
	SCRIPT_PYTHON
};

extern char *script_str;

#ifdef LIBMCOUNT
/* The below functions are used in libmcount in record time. */
extern int (*script_uftrace_entry)(struct mcount_ret_stack *rstack);
extern int (*script_uftrace_exit)(struct mcount_ret_stack *rstack, long *retval);

#else /* LIBMCOUNT */

/* The below functions are used for the recorded data. */
extern int (*script_uftrace_data_entry)(struct ftrace_task_handle *task,
					struct uftrace_record *rstack);
extern int (*script_uftrace_data_exit)(struct ftrace_task_handle *task,
				       struct uftrace_record *rstack,
				       uint64_t total_time);
#endif /* LIBMCOUNT */

int script_init(char *script_pathname);

#endif /* __UFTRACE_SCRIPT_H__ */
