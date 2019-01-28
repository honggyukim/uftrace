#!/usr/bin/env python

#
# Arguments / return type option tables generator for automatic value display
#
# Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
#
# Released under the GPL v2.
#

from __future__ import print_function
import sys
import re

# The syntax of C in Backus-Naur Form
#  https://cs.wmich.edu/~gupta/teaching/cs4850/sumII06/The%20syntax%20of%20C%20in%20Backus-Naur%20form.htm

# generated file name
argspec_file = "autoargs.h"

storage_class_specifier = ["auto", "register", "static", "extern", "typedef"]
type_qualifier = ["const", "volatile"]

type_specifier = ["void", "char", "short", "int", "long", "float", "double", \
                    "signed", "unsigned" ]

struct_or_union_specifier = ["struct", "union"]
enum_specifier = ["enum"]

typedef_name = [
        "size_t", "ssize_t", "pid_t", "off_t", "off64_t", "FILE",
        "sigset_t", "socklen_t", "intptr_t", "nfds_t",
        "pthread_t", "pthread_once_t", "pthread_attr_t",
        "pthread_mutex_t", "pthread_mutexattr_t",
        "Lmid_t",
    ]

artifitial_type = [ "funcptr_t" ]

pointer = "*"
reference = "&"

type_specifier.extend(struct_or_union_specifier)
#type_specifier.extend(enum_specifier)
type_specifier.extend(typedef_name)
type_specifier.extend(["std::string"])
type_specifier.extend(artifitial_type)

header = """\
/*
 * Arguments / return type option tables for automatic value display
 *
 * This file is auto-generated by "gen-autoargs.py" based on prototypes.h
 */

"""

verbose = False

def parse_return_type(words):
    global storage_class_specifier
    global type_qualifier
    global struct_or_union_specifier
    global enum_specifier
    global pointer

    i = 0
    return_type = ""
    struct_or_union_flag = False
    for word in words:
        if word in storage_class_specifier:
            # skip <storage-class-specifier>
            pass
        elif word in type_qualifier:
            # skip <type-qualifier>
            pass
        elif word in struct_or_union_specifier:
            return_type = word
            struct_or_union_flag = True
        elif word in type_specifier:
            if return_type == "":
                return_type = word
            else:
                return_type += " " + word
        elif word == pointer:
            return_type += word
        elif word == reference:
            # skip reference
            pass
        elif struct_or_union_flag:
            return_type += " " + word
            struct_or_union_flag = False
        elif word == ",":
            pass
        else:
            break
        i += 1
    return (return_type, words[i:])


def parse_func_name(words):
    funcname = words[0]
    return (funcname, words[1:])


def parse_args(words):
    if words[0] != '(' and words[-1] != ')':
        return []   # fail

    arg_type = []
    enum_flag = False
    struct_or_union_flag = False
    for word in words[1:-1]:
        if word in type_qualifier:
            # skip <type-qualifier>
            pass
        elif word in struct_or_union_specifier:
            arg_type.append(word)
            struct_or_union_flag = True
        elif word in type_specifier:
            arg_type.append(word)
        elif word in enum_specifier:
            enum_flag = True
        elif word == pointer:
            arg_type[-1] += pointer
        elif word == reference:
            # skip reference
            pass
        elif struct_or_union_flag:
            struct_or_union_flag = False
            arg_type[-1] += " " + word
        elif enum_flag:
            enum_flag = False
            arg_type.append("enum " + word)
        elif word == ",":
            pass
        else:
            struct_or_union_flag = False
            enum_flag = False
    return arg_type


def parse_func_decl(func):
    chunks = re.split('[\s,;]+|([*()])', func)
    words = [x for x in chunks if x]
    (return_type, words) = parse_return_type(words)
    (funcname, words) = parse_func_name(words)
    args = parse_args(words)
    return (return_type, funcname, args)


DECL_TYPE_NONE = 0
DECL_TYPE_FUNC = 1
DECL_TYPE_ENUM = 2

def get_decl_type(line):
    # function should have parenthesis
    if line.find('(') >= 0:
        return DECL_TYPE_FUNC
    # or it should be enum
    if line.startswith('enum'):
        return DECL_TYPE_ENUM
    # error
    return DECL_TYPE_NONE

def make_uftrace_retval_format(ctype, funcname):
    retval_format = funcname + "@"

    if ctype == "void":
        retval_format = ""
        pass
    elif ctype == "int":
        retval_format += "retval/d32"
    elif ctype == "short":
        retval_format += "retval/d16"
    elif ctype == "char":
        retval_format += "retval/c"
    elif ctype == "float":
        retval_format += "retval/f32"
    elif ctype == "double":
        retval_format += "retval/f64"
    elif ctype == "char*":
        retval_format += "retval/s"
    elif ctype == "std::string":
        retval_format += "retval/S"
    elif ctype[-1] == "*":
        retval_format += "retval/x"
    elif "unsigned" in ctype or ctype == "size_t" or ctype == "pid_t":
        retval_format += "retval/u"
    elif ctype == "funcptr_t":
        retval_format += "retval/p"
    elif ctype == "off64_t":
        retval_format += "retval/d64"
    elif ctype.startswith('enum'):
        retval_format += "retval/e:%s" % ctype[5:]
    else:
        retval_format += "retval"

    return retval_format


def make_uftrace_args_format(args, funcname):
    args_format = funcname + "@"

    i = 0
    f = 1
    for arg in args:
        i += 1
        if (i > 1):
            args_format += ","
        if arg == "void":
            args_format = ""
            break
        elif arg == "int":
            args_format += "arg%d/d32" % i
        elif arg == "short":
            args_format += "arg%d/d16" % i
        elif arg == "char":
            args_format += "arg%d/c" % i
        elif arg == "float":
            args_format += "fparg%d/32" % f
            f += 1
            i -= 1
        elif arg == "double":
            args_format += "fparg%d/64" % f
            f += 1
            i -= 1
        elif arg == "char*":
            args_format += "arg%d/s" % i
        elif arg == "std::string":
            args_format += "arg%d/S" % i
        elif arg[-1] == "*":
            args_format += "arg%d/x" % i
        elif "unsigned" in arg or arg == "size_t" or arg == "pid_t":
            args_format += "arg%d/u" % i
        elif arg == "funcptr_t":
            args_format += "arg%d/p" % i
        elif arg == "off64_t":
            args_format += "arg%d/d64" % i
        elif arg.startswith('enum'):
            args_format += "arg%d/e:%s" % (i, arg[5:])
        else:
            args_format += "arg%d" % i

    return args_format


def parse_enum(line):
    # is this the final line (including semi-colon)
    if line.find(';') >= 0:
        return (DECL_TYPE_NONE, ' '.join(line.split()))

    # continue to parse next line
    return (DECL_TYPE_ENUM, ' '.join(line.split()))


def parse_argument():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input-file", dest='infile', default="prototypes.h",
                        help="input prototype header file (default: prototypes.h")
    parser.add_argument("-o", "--output-file", dest='outfile', default="auto-args-list.h",
                        help="output uftrace argspec file (default: auto-args-list.h)")
    parser.add_argument("-v", "--verbose", dest='verbose', action='store_true',
                        help="show internal command and result for debugging")

    return parser.parse_args()


if __name__ == "__main__":
    arg = parse_argument()
    if arg.verbose:
        print(arg)

    argspec_file = arg.outfile
    prototype_file = arg.infile
    verbose = arg.verbose

    enum_list = ""
    args_list = ""
    retvals_list = ""

    # operator new and delete and their variations
    args_list     = '\t\"_Znwm@arg1/u;\"\n'   \
                  + '\t\"_Znam@arg1/u;\"\n'   \
                  + '\t\"_ZdlPv@arg1/x;\"\n'  \
                  + '\t\"_ZdaPv@arg1/x;\"\n'

    # operator new and its variations
    retvals_list  = '\t\"_Znwm@retval/x;\"\n' \
                  + '\t\"_Znam@retval/x;\"\n'

    t = DECL_TYPE_NONE
    with open(prototype_file) as fin:
        for line in fin:
            if len(line) <= 1 or line[0] == '#' or line[0:2] == "//" \
                    or line[0:7] == "typedef":
                continue

            if verbose:
                print(line, end='')

            if t == DECL_TYPE_ENUM:
                (t, curr) = parse_enum(line)
                enum_format += curr
                if t == DECL_TYPE_NONE:
                    enum_list += '\t"' + enum_format + '"\n'
                continue

            t = get_decl_type(line)
            if t == DECL_TYPE_NONE:
                continue
            if t == DECL_TYPE_ENUM:
                (t, enum_format) = parse_enum(line)
                if t == DECL_TYPE_NONE:
                    enum_list += '\t"' + enum_format + '"\n'
                continue

            (return_type, funcname, args) = parse_func_decl(line)
            if verbose:
                print(args)

            retval_format = make_uftrace_retval_format(return_type, funcname)
            args_format = make_uftrace_args_format(args, funcname)

            if verbose:
                print("ret : " + retval_format)
                print("arg : " + args_format)
                print("")

            if retval_format:
                retvals_list += '\t"' + retval_format + ';"\n'
            if args_format:
                args_list += '\t"' + args_format + ';"\n'

    if verbose:
        print(enum_list)
        print(args_list)
        print(retvals_list)

    if argspec_file == "-":
        fout = sys.stdout
    else:
        fout = open(argspec_file, "w")

    fout.write(header)

    if len(enum_list) == 0:
        enum_list="\"\""

    fout.write("static char *auto_enum_list =\n")
    fout.write(enum_list)
    fout.write(";\n\n")

    fout.write("static char *auto_args_list =\n")
    fout.write(args_list)
    fout.write(";\n\n")

    fout.write("static char *auto_retvals_list =\n")
    fout.write(retvals_list)
    fout.write(";\n\n")

    if argspec_file != "-":
        fout.close()
