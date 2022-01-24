#!/usr/bin/env python3

import argparse
import code
import itertools
import os
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Optional

# struct uftrace_file_header {
# 	char magic[UFTRACE_MAGIC_LEN];
# 	uint32_t version;
# 	uint16_t header_size;
# 	uint8_t  endian;
# 	uint8_t  elf_class;
# 	uint64_t feat_mask;
# 	uint64_t info_mask;
# 	uint16_t max_stack;
# 	uint16_t unused1;
# 	uint32_t unused2;
# };

#define UFTRACE_MAGIC_LEN  8
#define UFTRACE_MAGIC_STR  "Ftrace!"
#define UFTRACE_FILE_VERSION  4
#define UFTRACE_FILE_VERSION_MIN  3
#define UFTRACE_DIR_NAME     "uftrace.data"
#define UFTRACE_DIR_OLD_NAME  "ftrace.dir"
UFTRACE_MAGIC_LEN = 8
UFTRACE_MAGIC_STR = "Ftrace!"
UFTRACE_FILE_VERSION = 4
UFTRACE_FILE_VERSION_MIN = 3
UFTRACE_DIR_NAME = "uftrace.data"
UFTRACE_DIR_OLD_NAME = "ftrace.dir"

# struct uftrace_session_link {
# 	struct rb_root		root;
# 	struct rb_root		tasks;
# 	struct uftrace_session *first;
# 	struct uftrace_task    *first_task;
# };
#
# struct uftrace_data {
# 	FILE *fp;
# 	int sock;
# 	const char *dirname;
# 	enum uftrace_cpu_arch arch;
# 	struct uftrace_file_header hdr;
# 	struct uftrace_info info;
# 	struct uftrace_kernel_reader *kernel;
# 	struct uftrace_perf_reader *perf;
# 	struct uftrace_extern_reader *extn;
# 	struct uftrace_task_reader *tasks;
# 	struct uftrace_session_link sessions;
# 	int nr_tasks;
# 	int nr_perf;
# 	int last_perf_idx;
# 	int depth;
# 	bool needs_byte_swap;
# 	bool needs_bit_swap;
# 	bool perf_event_processed;
# 	bool caller_filter;
# 	uint64_t time_filter;
# 	struct uftrace_time_range time_range;
# 	struct list_head events;
# };

class uftrace_file_header:
    def __init__(self):
        self.magic = [None] * UFTRACE_MAGIC_LEN
        self.version = 32       # 32
        self.header_size = 16   # 16
        self.endian = 8        # 8
        self.elf_class = 8     # 8
        self.feat_mask = 64     # 64
        self.info_mask = 64     # 64
        self.max_stack = 16     # 16
        self.unused1 = 16       # 16
        self.unused2 = 32       # 32

# struct uftrace_info {
# 	char *exename;
# 	unsigned char build_id[20];
# 	int exit_status;
# 	char *cmdline;
# 	int nr_cpus_online;
# 	int nr_cpus_possible;
# 	char *cpudesc;
# 	char *meminfo;
# 	char *kernel;
# 	char *hostname;
# 	char *distro;
# 	char *argspec;
# 	char *retspec;
# 	char *autoarg;
# 	char *autoret;
# 	char *autoenum;
# 	bool auto_args_enabled;
# 	int nr_tid;
# 	int *tids;
# 	double stime;
# 	double utime;
# 	char *record_date;
# 	char *elapsed_time;
# 	long vctxsw;
# 	long ictxsw;
# 	long maxrss;
# 	long major_fault;
# 	long minor_fault;
# 	long rblock;
# 	long wblock;
# 	float load1;
# 	float load5;
# 	float load15;
# 	enum uftrace_pattern_type patt_type;
# 	char *uftrace_version;
# };
class uftrace_info:
    def __init__(self):
        self.exename = ""
        self.build_id = ""
        self.exit_status = 0
        self.cmdline = ""
#        self.nr_cpus_online = 0
#        self.nr_cpus_possible = 0
        self.nr_cpus = ""
        self.cpudesc = ""
        self.meminfo = ""
        self.kernel = ""
        self.hostname = ""
        self.distro = ""
        self.argspec = []
        self.retspec = []
        self.autoarg = []
        self.autoret = []
        self.autoenum = ""
        self.auto_args_enabled = False
        self.nr_tid = 0
        self.tids = []  # int *tids;
        self.stime = 0
        self.utime = 0
        self.record_data = ""
        self.elapsed_time = ""
        #self.vctxsw = 0
        #self.ictxsw = 0
        self.ctxsw = 0
        self.maxrss = 0
        #self.major_fault = 0
        #self.minor_fault = 0
        self.page_fault = 0
        #self.rblock = 0
        #self.wblock = 0
        self.iops = 0
        #self.load1 = 0
        #self.load5 = 0
        #self.load15 = 0
        self.loadinfo = 0
        self.patt_type = "" # 	enum uftrace_pattern_type patt_type;
        self.uftrace_version = ""
# };

class uftrace_data:
    def __init__(self):
        self.fp = None
        self.sock = 0
        self.dirname = ""
#	enum uftrace_cpu_arch arch;
        self.arch = ""
#	struct uftrace_file_header hdr;
#	struct uftrace_info info;
        self.info = uftrace_info()
#	struct uftrace_kernel_reader *kernel;
#	struct uftrace_perf_reader *perf;
#	struct uftrace_extern_reader *extn;
#	struct uftrace_task_reader *tasks;
#	struct uftrace_session_link sessions;
        self.sessions_root = None
        self.sessions_tasks = None
#	int nr_tasks;
#	int nr_perf;
        self.last_perf_idx = -1
        self.depth = 0
#	bool needs_byte_swap;
#	bool needs_bit_swap;
#	bool perf_event_processed;
#	bool caller_filter;
        self.time_filter = 0
        self.time_range = 0
#	struct list_head events;


    def __str__(self):
        return self.dirname

class opts:
    def __init__(self):
        self.dirname = "uftrace.data"
        self.depth = 0
        self.time_filter = 0
        self.time_range = 0

class uftrace_info_bits(Enum):
    EXE_NAME = 0
    EXE_BUILD_ID = 1
    EXIT_STATUS = 2
    CMDLINE = 3
    CPUINFO = 4
    MEMINFO = 5
    OSINFO = 6
    TASKINFO = 7
    USAGEINFO = 8
    LOADINFO = 9
    ARG_SPEC = 10
    RECORD_DATE = 11
    PATTERN_TYPE = 12
    VERSION = 13

# struct read_handler_arg {
# 	struct uftrace_data *handle;
# 	char buf[PATH_MAX];
# };
#
#
# static int read_exe_name(void *arg)
# {
# 	struct read_handler_arg *rha = arg;
# 	struct uftrace_data *handle = rha->handle;
# 	struct uftrace_info *info = &handle->info;
# 	char *buf = rha->buf;
#
# 	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
# 		return -1;
#
# 	if (strncmp(buf, "exename:", 8))
# 		return -1;
#
# 	info->exename = copy_info_str(&buf[8]);
#
# 	return 0;
# }
#
# int read_uftrace_info(uint64_t info_mask, struct uftrace_data *handle)
# {
# 	size_t i;
# 	struct read_handler_arg arg = {
# 		.handle = handle,
# 	};
# 	struct uftrace_info_handler read_handlers[] = {
# 		{ EXE_NAME,	read_exe_name },
# 		{ EXE_BUILD_ID,	read_exe_build_id },
# 		{ EXIT_STATUS,	read_exit_status },
# 		{ CMDLINE,	read_cmdline },
# 		{ CPUINFO,	read_cpuinfo },
# 		{ MEMINFO,	read_meminfo },
# 		{ OSINFO,	read_osinfo },
# 		{ TASKINFO,	read_taskinfo },
# 		{ USAGEINFO,	read_usageinfo },
# 		{ LOADINFO,	read_loadinfo },
# 		{ ARG_SPEC,	read_arg_spec },
# 		{ RECORD_DATE,	read_record_date },
# 		{ PATTERN_TYPE, read_pattern_type },
# 		{ VERSION,	read_uftrace_version },
# 	};
#
# 	memset(&handle->info, 0, sizeof(handle->info));
#
# 	for (i = 0; i < ARRAY_SIZE(read_handlers); i++) {
# 		if (!(info_mask & (1UL << read_handlers[i].bit)))
# 			continue;
#
# 		if (read_handlers[i].handler(&arg) < 0) {
# 			pr_dbg("error during read uftrace info (%x)\n",
# 			       (1U << read_handlers[i].bit));
# 			return -1;
# 		}
# 	}
# 	return 0;
# }

def read_exe_name(handle, info_bit):
    handle.info.exename = handle.fp.readline().decode('utf-8')[:-1]
    print(handle.info.exename)

def read_exe_build_id(handle, info_bit):
    handle.info.build_id = handle.fp.readline().decode('utf-8')[:-1]
    print(handle.info.build_id)

def read_exit_status(handle, info_bit):
    handle.info.exit_status = handle.fp.readline().decode('utf-8')[:-1]
    print(handle.info.exit_status)

def read_cmdline(handle, info_bit):
    handle.info.cmdline = handle.fp.readline().decode('utf-8')[:-1]
    print(handle.info.cmdline)

def read_cpuinfo(handle, info_bit):
    cpuinfo_lines = handle.fp.readline().decode('utf-8')[:-1]
    assert cpuinfo_lines.startswith("cpuinfo:lines=")
    cpuinfo_lines = int(cpuinfo_lines[14:])
    for i in range(cpuinfo_lines):
        line = handle.fp.readline().decode('utf-8')
        if line.startswith("cpuinfo:nr_cpus="):
            handle.info.nr_cpus = line[:-1]
        elif line.startswith("cpuinfo:desc="):
            handle.info.cpudesc = line[13:-1]
            cpudesc = handle.info.cpudesc
            if cpudesc.startswith("ARMv6") or cpudesc.startswith("ARMv7"):
                handle.arch = "UFT_CPU_ARM"
            elif cpudesc.startswith("ARM64"):
                handle.arch = "UFT_CPU_AARCH64"
            elif data_is_lp64(handle):
                handle.arch = "UFT_CPU_X86_64"
            else:
                handle.arch = "UFT_CPU_I386"
    print(handle.info.nr_cpus)
    print(handle.info.cpudesc)
    print(handle.arch)

def read_meminfo(handle, info_bit):
    handle.info.meminfo = handle.fp.readline().decode('utf-8')[:-1]
    print(handle.info.meminfo)

def read_osinfo(handle, info_bit):
    osinfo_lines = handle.fp.readline().decode('utf-8')[:-1]
    assert osinfo_lines.startswith("osinfo:lines=")
    osinfo_lines = int(osinfo_lines[13:])
    for i in range(osinfo_lines):
        line = handle.fp.readline().decode('utf-8')[:-1]
        if line.startswith("osinfo:kernel="):
            handle.info.kernel = line
        elif line.startswith("osinfo:hostname="):
            handle.info.hostname = line
        elif line.startswith("osinfo:distro="):
            handle.info.distro = line
    print(handle.info.kernel)
    print(handle.info.hostname)
    print(handle.info.distro)

def read_taskinfo(handle, info_bit):
    taskinfo_lines = handle.fp.readline().decode('utf-8')[:-1]
    assert taskinfo_lines.startswith("taskinfo:lines=")
    taskinfo_lines = int(taskinfo_lines[15:])
    for i in range(taskinfo_lines):
        line = handle.fp.readline().decode('utf-8')[:-1]
        if line.startswith("taskinfo:nr_tid="):
            handle.info.nr_tid = int(line[len("taskinfo:nr_tid="):])
            print(handle.info.nr_tid)
        elif line.startswith("taskinfo:tids="):
            handle.info.tids = line[len("taskinfo:tids="):].split(',')
            print(handle.info.tids)

def read_usageinfo(handle, info_bit):
    usageinfo_lines = handle.fp.readline().decode('utf-8')[:-1]
    assert usageinfo_lines.startswith("usageinfo:lines=")
    usageinfo_lines = int(usageinfo_lines[16:])
    for i in range(usageinfo_lines):
        line = handle.fp.readline().decode('utf-8')[:-1]
        if line.startswith("usageinfo:systime="):
            handle.info.stime = line
        elif line.startswith("usageinfo:usrtime="):
            handle.info.utime = line
        elif line.startswith("usageinfo:ctxsw="):
            handle.info.ctxsw = line
        elif line.startswith("usageinfo:maxrss="):
            handle.info.maxrss = line
        elif line.startswith("usageinfo:pagefault="):
            handle.info.page_fault = line
        elif line.startswith("usageinfo:iops="):
            handle.info.iops = line
    print(handle.info.stime)
    print(handle.info.utime)
    print(handle.info.ctxsw)
    print(handle.info.maxrss)
    print(handle.info.page_fault)
    print(handle.info.iops)

def read_loadinfo(handle, info_bit):
    handle.info.loadinfo = handle.fp.readline().decode('utf-8')[:-1]
    assert handle.info.loadinfo.startswith("loadinfo:")
    print(handle.info.loadinfo)

def read_arg_spec(handle, info_bit):
    argspec_lines = handle.fp.readline().decode('utf-8')[:-1]
    assert argspec_lines.startswith("argspec:lines=")
    argspec_lines = int(argspec_lines[14:])
    for i in range(argspec_lines):
        line = handle.fp.readline().decode('utf-8')[:-1]
        if line.startswith("argspec:"):
            handle.info.argspec = line[len("argspec:"):].split(';')[:-1]
            print(handle.info.argspec)
        elif line.startswith("retspec:"):
            handle.info.retspec = line[len("retspec:"):].split(';')[:-1]
            print(handle.info.retspec)
        elif line.startswith("argauto:"):
            handle.info.autoarg = line[len("argauto:"):].split(';')[:-1]
            print(handle.info.autoarg)
        elif line.startswith("retauto:"):
            handle.info.autoret = line[len("retspec:"):].split(';')[:-1]
            print(handle.info.autoret)
        elif line.startswith("enumauto:"):
            handle.info.autoenum = line
            print(handle.info.autoenum)
        elif line.startswith("auto-args:"):
            handle.info.auto_args_enabled = bool(line[len("auto-args:"):])
            print(handle.info.auto_args_enabled)

def read_record_date(handle, info_bit):
    handle.info.record_date = handle.fp.readline().decode('utf-8')[:-1]
    assert handle.info.record_date.startswith("record_date:")
    print(handle.info.record_date)
    handle.info.elapsed_time = handle.fp.readline().decode('utf-8')[:-1]
    assert handle.info.elapsed_time.startswith("elapsed_time:")
    print(handle.info.elapsed_time)

def read_pattern_type(handle, info_bit):
    handle.info.patt_type = handle.fp.readline().decode('utf-8')[:-1]
    assert handle.info.patt_type.startswith("pattern_type:")
    print(handle.info.patt_type)

def read_uftrace_version(handle, info_bit):
    handle.info.uftrace_version = handle.fp.readline().decode('utf-8')[:-1]
    assert handle.info.uftrace_version.startswith("uftrace_version:")
    print(handle.info.uftrace_version)

def read_uftrace_info(info_mask, handle):
    read_exe_name(handle, uftrace_info_bits.EXE_NAME)
    read_exe_build_id(handle, uftrace_info_bits.EXE_BUILD_ID)
    read_exit_status(handle, uftrace_info_bits.EXIT_STATUS)
    read_cmdline(handle, uftrace_info_bits.CMDLINE)
    read_cpuinfo(handle, uftrace_info_bits.CPUINFO)
    read_meminfo(handle, uftrace_info_bits.MEMINFO)
    read_osinfo(handle, uftrace_info_bits.OSINFO)
    read_taskinfo(handle, uftrace_info_bits.TASKINFO)
    read_usageinfo(handle, uftrace_info_bits.USAGEINFO)
    read_loadinfo(handle, uftrace_info_bits.LOADINFO)
    read_arg_spec(handle, uftrace_info_bits.ARG_SPEC)
    read_record_date(handle, uftrace_info_bits.RECORD_DATE)
    read_pattern_type(handle, uftrace_info_bits.PATTERN_TYPE)
    read_uftrace_version(handle, uftrace_info_bits.VERSION)

def data_is_lp64(handle):
    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2
    return handle.hdr.elf_class == ELFCLASS64

def open_info_file(opts, handle):
    with open("%s/info" % opts.dirname, "rb") as f:
        handle.fp = f
        handle.dirname = opts.dirname
        handle.depth = opts.depth
        handle.time_filter = opts.time_filter
        handle.time_range = opts.time_range
        handle.sessions_root = None
        handle.sessions_tasks = None
        handle.last_perf_idx = -1

        handle.hdr = uftrace_file_header()

        handle.hdr.magic = f.read(UFTRACE_MAGIC_LEN).decode('utf-8')
        handle.hdr.version = f.read(4)[0]
        handle.hdr.header_size = f.read(2)
        handle.hdr.endian = f.read(1)
        handle.hdr.elf_class = f.read(1)[0]
        handle.hdr.feat_mask = f.read(8)
        handle.hdr.info_mask = f.read(8)
        handle.hdr.max_stack = f.read(2)
        handle.hdr.unused1 = f.read(2)
        handle.hdr.unused2 = f.read(4)

        if handle.hdr.magic[:-1] != UFTRACE_MAGIC_STR:
            assert handle.hdr.magic[:-1] == UFTRACE_MAGIC_STR
            print("invalid magic string found!");
            return

        if handle.hdr.version < UFTRACE_FILE_VERSION_MIN or handle.hdr.version > UFTRACE_FILE_VERSION:
            print("unsupported file version '%s' not matched" % handle.hdr.version)
            return

        read_uftrace_info(handle.hdr.info_mask, handle)


def open_data_file(opts, handle):
    open_info_file(opts, handle)

opts = opts()
handle = uftrace_data()
open_data_file(opts, handle)

# int open_info_file(struct opts *opts, struct uftrace_data *handle)
# {
# 	FILE *fp;
# 	char buf[PATH_MAX];
# 	int saved_errno = 0;
# 	struct stat stbuf;
#
# 	memset(handle, 0, sizeof(*handle));
#
# 	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);
#
# 	fp = fopen(buf, "rb");
# 	if (fp != NULL)
# 		goto ok;
#
# 	saved_errno = errno;
# 	/* provide a better error code for empty/invalid directories */
# 	if (stat(opts->dirname, &stbuf) == 0)
# 		saved_errno = EINVAL;
#
# 	/* if default dirname is failed */
# 	if (!strcmp(opts->dirname, UFTRACE_DIR_NAME)) {
# 		/* try again inside the current directory */
# 		fp = fopen("./info", "rb");
# 		if (fp != NULL) {
# 			opts->dirname = "./";
# 			goto ok;
# 		}
#
# 		/* retry with old default dirname */
# 		snprintf(buf, sizeof(buf), "%s/info", UFTRACE_DIR_OLD_NAME);
# 		fp = fopen(buf, "rb");
# 		if (fp != NULL) {
# 			opts->dirname = UFTRACE_DIR_OLD_NAME;
# 			goto ok;
# 		}
#
# 		saved_errno = errno;
#
# 		/* restore original file name for error reporting */
# 		snprintf(buf, sizeof(buf), "%s/info", opts->dirname);
# 	}
#
# 	/* data file loading is failed */
# 	pr_dbg("cannot open %s file\n", buf);
#
# 	return -saved_errno;
# ok:
# 	saved_errno = 0;
# 	handle->fp = fp;
# 	handle->dirname = opts->dirname;
# 	handle->depth = opts->depth;
# 	handle->time_filter = opts->threshold;
# 	handle->time_range = opts->range;
# 	handle->sessions.root  = RB_ROOT;
# 	handle->sessions.tasks = RB_ROOT;
# 	handle->last_perf_idx = -1;
# 	INIT_LIST_HEAD(&handle->events);
#
# 	if (fread(&handle->hdr, sizeof(handle->hdr), 1, fp) != 1)
# 		pr_err("cannot read header data");
#
# 	if (memcmp(handle->hdr.magic, UFTRACE_MAGIC_STR, UFTRACE_MAGIC_LEN))
# 		pr_err_ns("invalid magic string found!\n");
#
# 	check_data_order(handle);
#
# 	if (handle->needs_byte_swap) {
# 		handle->hdr.version   = bswap_32(handle->hdr.version);
# 		handle->hdr.feat_mask = bswap_64(handle->hdr.feat_mask);
# 		handle->hdr.info_mask = bswap_64(handle->hdr.info_mask);
# 		handle->hdr.max_stack = bswap_16(handle->hdr.max_stack);
# 	}
#
# 	if (handle->hdr.version < UFTRACE_FILE_VERSION_MIN ||
# 	    handle->hdr.version > UFTRACE_FILE_VERSION)
# 		pr_err_ns("unsupported file version: %u\n", handle->hdr.version);
#
# 	if (read_uftrace_info(handle->hdr.info_mask, handle) < 0)
# 		pr_err_ns("cannot read uftrace header info!\n");
#
# 	if (opts->exename == NULL)
# 		opts->exename = handle->info.exename;
#
# 	fclose(fp);
# 	return 0;
# }

# int open_data_file(struct opts *opts, struct uftrace_data *handle)
# {
# 	int ret;
# 	char buf[PATH_MAX];
# 	int saved_errno = 0;
#
# 	ret = open_info_file(opts, handle);
# 	if (ret < 0) {
# 		errno = -ret;
# 		return -1;
# 	}
#
# 	if (handle->info.nr_tid == 0) {
# 		errno = ENODATA;
# 		return -1;
# 	}
#
# 	if (handle->hdr.feat_mask & TASK_SESSION) {
# 		bool sym_rel = false;
# 		struct uftrace_session_link *sessions = &handle->sessions;
# 		int i;
#
# 		if (handle->hdr.feat_mask & SYM_REL_ADDR)
# 			sym_rel = true;
#
# 		/* read old task file first and then try task.txt file */
# 		if (read_task_file(sessions, opts->dirname, true, sym_rel,
# 				   opts->srcline) < 0 &&
# 		    read_task_txt_file(sessions, opts->dirname,
# 				       opts->with_syms ?: opts->dirname,
# 				       true, sym_rel, opts->srcline) < 0) {
# 			if (errno == ENOENT)
# 				saved_errno = ENODATA;
# 			else
# 				saved_errno = errno;
#
# 			goto out;
# 		}
#
# 		if (sessions->first == NULL) {
# 			saved_errno = EINVAL;
# 			goto out;
# 		}
#
# 		for (i = 0; i < handle->info.nr_tid; i++) {
# 			int tid = handle->info.tids[i];
#
# 			if (find_task(sessions, tid))
# 				break;
# 		}
#
# 		if (i == handle->info.nr_tid) {
# 			saved_errno = ENODATA;
# 			goto out;
# 		}
# 	}
#
# 	if (handle->hdr.info_mask & ARG_SPEC) {
# 		struct uftrace_filter_setting setting = {
# 			.ptype		= handle->info.patt_type,
# 			.allow_kernel	= true,
# 			.auto_args	= false,
# 			.lp64		= data_is_lp64(handle),
# 			.arch		= handle->arch,
# 		};
#
# 		if (handle->hdr.feat_mask & AUTO_ARGS) {
# 			setup_auto_args_str(handle->info.autoarg,
# 					    handle->info.autoret,
# 					    handle->info.autoenum,
# 					    &setting);
# 		}
#
# 		setup_fstack_args(handle->info.argspec, handle->info.retspec,
# 				  handle, &setting);
#
# 		if (handle->info.auto_args_enabled) {
# 			char *autoarg = handle->info.autoarg;
# 			char *autoret = handle->info.autoret;
#
# 			if (handle->hdr.feat_mask & DEBUG_INFO) {
# 				if (handle->info.patt_type == PATT_REGEX)
# 					autoarg = autoret = ".";
# 				else  /* PATT_GLOB */
# 					autoarg = autoret = "*";
# 			}
#
# 			setting.auto_args = true;
# 			setup_fstack_args(autoarg, autoret, handle, &setting);
# 		}
# 	}
#
# 	if (!(handle->hdr.feat_mask & MAX_STACK))
# 		handle->hdr.max_stack = MCOUNT_RSTACK_MAX;
#
# 	if (handle->hdr.feat_mask & KERNEL) {
# 		struct uftrace_kernel_reader *kernel;
#
# 		kernel = xzalloc(sizeof(*kernel));
#
# 		kernel->handle   = handle;
# 		kernel->dirname  = opts->dirname;
# 		kernel->skip_out = opts->kernel_skip_out;
#
# 		if (setup_kernel_data(kernel) == 0) {
# 			handle->kernel = kernel;
# 			load_kernel_symbol(opts->dirname);
# 		}
# 		else {
# 			free(kernel);
# 			handle->kernel = NULL;
# 		}
# 	}
#
# 	if (handle->hdr.feat_mask & EVENT)
# 		read_events_file(handle);
#
# 	if (handle->hdr.feat_mask & PERF_EVENT)
# 		setup_perf_data(handle);
#
# 	setup_extern_data(handle, opts);
#
# 	/* check there are data files actually */
# 	snprintf(buf, sizeof(buf), "%s/[0-9]*.dat", opts->dirname);
# 	if (!check_data_file(handle, buf)) {
# 		if (handle->kernel) {
# 			snprintf(buf, sizeof(buf), "%s/kernel-*.dat",
# 				 opts->dirname);
#
# 			if (check_data_file(handle, buf))
# 				goto out;
# 		}
#
# 		if (saved_errno == 0)
# 			saved_errno = ENODATA;
# 	}
#
# out:
# 	if (saved_errno) {
# 		close_data_file(opts, handle);
# 		errno = saved_errno;
# 		ret = -1;
# 	}
# 	else
# 		ret = 0;
#
# 	return ret;
# }
