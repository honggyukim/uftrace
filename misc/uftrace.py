import sys
import trace_python
import os

progname = sys.argv[1]

globs = {
    '__file__': progname,
    '__name__': '__main__',
    '__package__': None,
    '__cached__': None,
}

sys.settrace(trace_python.trace)

exec(open(progname).read(), globs, globs)
