#!/usr/bin/env python

#
# uftrace-option: --nest-libcall -T malloc@filter,arg1,retval -T free@filter,arg1 -T calloc@filter,arg1,arg2,retval -T realloc@filter,arg1,arg2,retval -T strdup@filter,arg1,retval -T strndup@filter,arg1,arg2,retval -T __strdup@filter,arg1/s,retval -T strdupa@filter,arg1,retval -T strndupa@filter,arg1,arg2,retval -T asprintf@filter,arg1,arg2,retval -T __asprintf_chk@filter,arg1,arg2,retval -T vasprintf@filter,arg1,arg2,retval -T posix_memalign@filter,arg1,arg2,arg3,retval -T aligned_alloc@filter,arg1,arg2,retval -T valloc@filter,arg1,retval -T memalign@filter,arg1,arg2,retval -T pvalloc@filter,arg1,retval -T realpath@filter,arg1,arg2,retval -T __realpath_chk@filter,arg1,arg2,retval

#
#   void *malloc(size_t size);
#   void free(void *ptr);
#   void *calloc(size_t nmemb, size_t size);
#   void *realloc(void *ptr, size_t size);
#
#   char *strdup(const char *s);
#   char *strndup(const char *s, size_t n);
#   char *strdupa(const char *s);
#   char *strndupa(const char *s, size_t n);
#
#   int asprintf(char **strp, const char *fmt, ...);
#   int vasprintf(char **strp, const char *fmt, va_list ap);
#
#   int posix_memalign(void **memptr, size_t alignment, size_t size);
#   void *aligned_alloc(size_t alignment, size_t size);
#   void *valloc(size_t size);
#
#   void *memalign(size_t alignment, size_t size);
#   void *pvalloc(size_t size);
#
#   char *realpath(const char *path, char *resolved_path);
#

#UFTRACE_FUNCS = [ "malloc", "free", "calloc", "realloc", "asprintf", "vasprintf", "strdup", "strndup", "strdupa", "strndupa", "__strdup", "__asprintf_chk" ]
UFTRACE_FUNCS = [ "malloc", "free", "calloc", "realloc", "asprintf", "vasprintf", "strdup", "strndup", "strdupa", "strndupa", "__strdup", "__asprintf_chk", "posix_memalign", "aligned_alloc", "valloc", "memalign", "pvalloc", "realpath", "__realpath_chk" ]

current = 0
size = 0
addr = 0
begin_timestamp = 0
nmemb = 0
resolved_path = 0

malloc_map   = {}   # { key: address, value: memory size allocated at this address }
timeline_arr = []   # elapsed time
mem_usage_arr = []  # total memory usage in bytes

def uftrace_begin():
    print("")
    print("   ELAPSED TIME   FUNCTION                    ADDRESS           ALLOCATED BYTES")
    print("  ==============================================================================")


def uftrace_entry(ctx):
    global current
    global size
    global addr
    global malloc_map
    global timeline_arr
    global mem_usage_arr
    global begin_timestamp
    global nmemb
    global resolved_path

    _name = ctx["name"]
    _timestamp = ctx["timestamp"]

    if begin_timestamp is 0:
        begin_timestamp = _timestamp

    if _name == "malloc":
        size = ctx["args"][0]
    elif _name == "calloc":
        # calloc(size_t nmemb, size_t size)
        nmemb = ctx["args"][0]
        size  = ctx["args"][1]
    elif _name == "realloc":
        # void *realloc(void *ptr, size_t size);
        addr = ctx["args"][0]
        size = ctx["args"][1]
    elif _name == "free":
        # void free(void *ptr);
        addr = ctx["args"][0]
        free_call = "free(%#x)" % addr
        if malloc_map.has_key(hex(addr)):
            free_size = malloc_map[hex(addr)]
            current -= malloc_map[hex(addr)]
            del malloc_map[hex(addr)]
        elif addr is 0:
            free_size = "xxx"
        else:
            print("")
            print("  %13s   INVALID ADDRESS FREE" % "")
            free_size = "xxx"
        elapsed_time = _timestamp - begin_timestamp
        timeline_arr.append(elapsed_time)
        mem_usage_arr.append(current)
        print("  %13d : %-25s   %-14s    %d (-%s)" % (elapsed_time, free_call, "", current, free_size))
    elif _name == "__realpath_chk":
        # char *realpath(const char *path, char *resolved_path);
        resolved_path = ctx["args"][1]

def uftrace_exit(ctx):
    global current
    global size
    global addr
    global malloc_map
    global timeline_arr
    global mem_usage_arr
    global begin_timestamp

    _name = ctx["name"]
    _timestamp = ctx["timestamp"]
    elapsed_time = _timestamp - begin_timestamp

    if _name == "malloc":
        # void *malloc(size_t size);
        addr = ctx["retval"]
        malloc_map[hex(addr)] = size
        current += size
        timeline_arr.append(elapsed_time)
        mem_usage_arr.append(current)
        malloc_call = "malloc(%d)" % size
        print("  %13d : %-25s = %#-14x    %d" % (elapsed_time, malloc_call, addr, current))
    elif _name == "calloc":
        # void *calloc(size_t nmemb, size_t size);
        addr = ctx["retval"]
        malloc_map[hex(addr)] = nmemb * size
        current += nmemb * size
        timeline_arr.append(elapsed_time)
        mem_usage_arr.append(current)
        calloc_call = "calloc(%d, %d)" % (nmemb, size)
        print("  %13d : %-25s = %#-14x    %d" % (elapsed_time, calloc_call, addr, current))
    elif _name == "realloc":
        # void *realloc(void *ptr, size_t size);
        current -= malloc_map[hex(addr)]
        del malloc_map[hex(addr)]
        realloc_call = "realloc(%#x, %d)" % (addr, size)

        addr = ctx["retval"]
        malloc_map[hex(addr)] = size
        current += size
        timeline_arr.append(elapsed_time)
        mem_usage_arr.append(current)
        print("  %13d : %-25s = %#-14x    %d" % (elapsed_time, realloc_call, addr, current))
    elif _name == "__strdup":
        #retstr = ctx["retval"]
        #strdup_call = "__strdup() = %d" % (len(retstr) + 1)

        addr = ctx["retval"]
        strdup_call = "__strdup(%#x)" % addr

        #current += 0
        malloc_map[hex(addr)] = 0

        print("  %13d : %-25s = %#-14x    %d" % (elapsed_time, strdup_call, addr, current))
        #print(" *** exit  : %s() = %s (%d) ***" % (_name, retstr, len(retstr)))
    elif _name == "__realpath_chk":
        #retstr = ctx["retval"]
        #strdup_call = "__realpath_chk() = %d" % (len(retstr) + 1)

        addr = ctx["retval"]
        realpath_call = "__realpath_chk(%#x)" % resolved_path

        #current += 0
        malloc_map[hex(addr)] = 0

        print("  %13d : %-25s = %#-14x    %d" % (elapsed_time, realpath_call, addr, current))
    elif _name != "free":
        print("  *** exit : %s() ***" % _name)

def uftrace_end():
    global current
    global malloc_map
    print("  =========================================================================\n")
    if current is not 0:
        print("")
        print("  * %d bytes are not free-ed in %d objects" % (current, len(malloc_map)))
        print("")
        print("    NON-FREE ADDRESS          SIZE (bytes)")
        print("  =========================================================================")
        for key, value in malloc_map.items():
            print("     %#15s          %d" % (key[:-1], value))
        print("  =========================================================================")
        print("")
