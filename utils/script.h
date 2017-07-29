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
typedef int (*script_uftrace_entry_fp)(struct mcount_ret_stack *rstack,
				       char *symname);

typedef int (*script_uftrace_exit_fp)(struct mcount_ret_stack *rstack,
				      char *symname, long *retval);

/* The below functions are used in libmcount in record time. */
extern script_uftrace_entry_fp script_uftrace_entry;
extern script_uftrace_exit_fp script_uftrace_exit;

#else /* LIBMCOUNT */

/* The below functions are used for the recorded data. */
typedef int (*script_uftrace_data_entry_fp)(struct ftrace_task_handle *task,
					    struct uftrace_record *rstack,
					    char *symname);
typedef int (*script_uftrace_data_exit_fp)(struct ftrace_task_handle *task,
					   struct uftrace_record *rstack,
					   char *symname,
					   uint64_t total_time);

/* The below functions are used for the recorded data. */
extern script_uftrace_data_entry_fp script_uftrace_data_entry;
extern script_uftrace_data_exit_fp script_uftrace_data_exit;
#endif /* LIBMCOUNT */

int script_init(char *script_pathname);

#endif /* __UFTRACE_SCRIPT_H__ */
