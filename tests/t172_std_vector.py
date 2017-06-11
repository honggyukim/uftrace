#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'std-vector', lang='C++', cflags='-std=c++11', result="""
# DURATION    TID     FUNCTION
            [  801] | main() {
   1.340 us [  801] |   std_vector_arg(std::vector{raw_size: 20, capacity: 20});
   3.780 us [  801] |   std_vector_ret() = std::vector{raw_size: 24, capacity: 24};
   0.233 us [  801] |   std_vector_arg(std::vector{raw_size: 24, capacity: 40});
   0.207 us [  801] |   std_vector_arg(std::vector{raw_size: 28, capacity: 40});
  18.797 us [  801] | } /* main */
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
