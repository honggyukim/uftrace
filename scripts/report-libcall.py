#
# report-libcall.py
#
# uftrace-option: --nest-libcall -F .*@plt
#

import operator

libcall_map = {}

def uftrace_begin():
    pass

def uftrace_entry(ctx):
    _name = ctx["name"]
    if libcall_map.has_key(_name):
        libcall_map[_name] += 1
    else:
        libcall_map[_name] = 1

def uftrace_exit(ctx):
    pass

def uftrace_end():
    global libcall_map
    sorted_dict = sorted(libcall_map.items(), key=operator.itemgetter(1), reverse=True)
    print("  %15s       %-#50s" % ("Call Count", "Library Functions"))
    print("  ===================================================================")
    for item in sorted_dict:
        print("  %15d       %-#50s" % (item[1], item[0]))
    print("  ===================================================================")
