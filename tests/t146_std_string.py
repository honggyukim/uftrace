#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'std-string', lang='C++', result="""
# DURATION    TID     FUNCTION
            [71555] | main() {
   7.549 us [71555] |   std_string_arg("Hello");
   0.218 us [71555] |   std_string_arg("World!");
   0.150 us [71555] |   std_string_arg("Hello World!");
   0.240 us [71555] |   std_string_ret::cxx11() = "Hello";
   0.124 us [71555] |   std_string_ret::cxx11() = "World!";
   0.110 us [71555] |   std_string_ret::cxx11() = "Hello World!";
  10.346 us [71555] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def runcmd(self):
        arg = '-A ^std_string_arg@arg1/S'
        retval = '-R ^std_string_ret@retval/S'
        opts = '-F main -F ^std_string_ -D 1'
        name = 't-' + self.name
        return '%s %s %s %s %s' % (TestBase.ftrace, arg, retval, opts, name)
