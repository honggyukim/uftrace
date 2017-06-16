indent = 0

def uftrace_entry(args):
    global indent
    space = " " * indent

    buf = "%s%s() {" % (space, args["symname"])
    print(buf)
    indent += 2
    return args["entry_addr"]

def uftrace_exit(args):
    global indent
    indent -= 2
    space = " " * indent

    buf = "%s}" % space
    if args["retval"]:
        buf += " = %s" % str(args["retval"])
    buf += ";"
    print(buf)
    return args["ret_addr"]
