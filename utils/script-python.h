/*
 * Python script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#ifndef __UFTRACE_SCRIPT_PYTHON_H__
#define __UFTRACE_SCRIPT_PYTHON_H__

#include <python2.7/Python.h>

int script_init_for_python(char *py_pathname);

#endif /* __UFTRACE_SCRIPT_PYTHON_H__ */
