/*
 * Script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */

/* This will be set by getenv("UFTRACE_SCRIPT") */
char *script_str;

int (*script_uftrace_entry)(unsigned long entry_addr, unsigned long ret_addr);
int (*script_uftrace_exit)(unsigned long ret_addr, long *retval);
