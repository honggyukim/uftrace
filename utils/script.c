/*
 * Script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include "utils/script.h"


/* This will be set by getenv("UFTRACE_SCRIPT"). */
char *script_str;


#ifdef LIBMCOUNT
/* The below functions are used in libmcount in record time. */
int (*script_uftrace_entry)(struct mcount_ret_stack *rstack,
			    char *symname);
int (*script_uftrace_exit)(struct mcount_ret_stack *rstack,
			   char *symname,
			   long *retval);

#else /* LIBMCOUNT */

/* The below functions are used for the recorded data. */
int (*script_uftrace_data_entry)(struct ftrace_task_handle *task,
				 struct uftrace_record *rstack,
				 char *symname);
int (*script_uftrace_data_exit)(struct ftrace_task_handle *task,
				struct uftrace_record *rstack,
				char *symname,
				uint64_t total_time);
#endif /* LIBMCOUNT */


#if HAVE_LIBPYTHON2

static enum script_type_t get_script_type(const char *str)
{
	char *ext = strrchr(str, '.');

	/*
	 * The given script will be detected by the file suffix.
	 * As of now, it only handles ".py" suffix for python.
	 */
	if (!strcmp(ext, ".py"))
		return SCRIPT_PYTHON;

	return SCRIPT_UNKNOWN;
}

int script_init(char *script_pathname)
{
	if (!script_pathname)
		return -1;

	switch (get_script_type(script_pathname)) {
	case SCRIPT_PYTHON:
		if (script_init_for_python(script_pathname) < 0)
			script_pathname = NULL;
		break;
	default:
		script_pathname = NULL;
	}

	return 0;
}

#else /* HAVE_LIBPYTHON2 */

int script_init(char *script_pathname)
{
	/* Do nothing if libpython2.7.so is not installed. */
	return 0;
}

#endif /* HAVE_LIBPYTHON2 */
