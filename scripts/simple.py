def uftrace_entry(args):
    _symname = args["symname"]
    print("entry : " + _symname + "()")
    return args["entry_addr"]

def uftrace_exit(args):
    _symname = args["symname"]
    print("exit  : " + _symname + "()")
