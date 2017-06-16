/*
 * Python binding for mcount entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#include <python2.7/Python.h>

int python_init(const char *pyfile);
int python_mcount_entry(unsigned long entry_addr, unsigned long ret_addr);
int python_mcount_exit(unsigned long ret_addr, long *retval);
