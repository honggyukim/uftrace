/*
 * Script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#ifndef SCRIPT_H
#define SCRIPT_H

extern char *script_str;

extern int (*script_uftrace_entry)(unsigned long entry_addr, unsigned long ret_addr);
extern int (*script_uftrace_exit)(unsigned long ret_addr, long *retval);

#endif
