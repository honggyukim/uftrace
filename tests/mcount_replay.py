indent = 0

def mcount_entry(entry_addr, ret_addr):
    global indent
    space = " " * indent

    buf = "%s%s() {" % (space, hex(entry_addr))
    print(buf)
    indent += 2
    return entry_addr

def mcount_exit(ret_addr, retval = None):
    global indent
    indent -= 2
    space = " " * indent

    buf = "%s}" % space
    if retval:
        buf += " = %s" % str(retval)
    buf += ";"
    print(buf)
    return ret_addr
