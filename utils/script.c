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
script_uftrace_entry_fp script_uftrace_entry;
script_uftrace_exit_fp script_uftrace_exit;

#else /* LIBMCOUNT */

/* The below functions are used for the recorded data. */
script_uftrace_data_entry_fp script_uftrace_data_entry;
script_uftrace_data_exit_fp script_uftrace_data_exit;
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
