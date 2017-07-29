/*
 * Python script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#ifndef __UFTRACE_SCRIPT_PYTHON_H__
#define __UFTRACE_SCRIPT_PYTHON_H__

#if HAVE_LIBPYTHON2

#include <python2.7/Python.h>

int script_init_for_python(char *py_pathname);

#else

/* Trust the compiler to optimize out its related code. */
#define HAVE_LIBPYTHON2 0

#endif /* HAVE_LIBPYTHON2 */

#endif /* __UFTRACE_SCRIPT_PYTHON_H__ */
