/*
 * Script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#ifndef SCRIPT_H
#define SCRIPT_H

#include <python2.7/Python.h>
#include "libmcount/mcount.h"

extern char *script_str;

/* The below functions are used in libmcount at record time. */
extern int (*script_uftrace_entry)(struct mcount_ret_stack *rstack);
extern int (*script_uftrace_exit)(struct mcount_ret_stack *rstack, long *retval);

/* The below functions are used for the recorded data. */
extern int (*script_uftrace_data_entry)(struct ftrace_task_handle *task,
					struct uftrace_record *rstack);
extern int (*script_uftrace_data_exit)(struct ftrace_task_handle *task,
				       struct uftrace_record *rstack,
				       uint64_t total_time);

int python_init(char *py_pathname);

#endif
