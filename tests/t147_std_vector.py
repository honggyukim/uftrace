#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'std-vector', lang='C++', cflags='-std=c++11', result="""
# DURATION    TID     FUNCTION
            [377912] | main() {
   1.105 us [377912] |   std_vector_arg({1, 2, 3, 4, 5, 6, 7});
   2.431 us [377912] |   std_vector_ret() = {1, 2, 3, 4, 5, 6, 7};
   7.121 us [377912] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def runcmd(self):
        arg = '-A ^std_vector_arg@arg1/V'
        retval = '-R ^std_vector_ret@retval/V'
        opts = '-F main -F ^std_vector_ -D 1'
        name = 't-' + self.name
        return '%s %s %s %s %s' % (TestBase.ftrace, arg, retval, opts, name)
