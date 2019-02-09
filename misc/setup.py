#!/usr/bin/env python3
# encoding: utf-8

from distutils.core import setup, Extension

hello_module = Extension('trace_python', sources = ['trace-python.c'])

setup(name='trace_python',
      version='0.1.0',
      description='Trace Python module for uftrace',
      ext_modules=[trace_python])
