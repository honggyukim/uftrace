#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
Total time,Self time,Calls,Function
11.543 ms,838.851 us,1,main
10.365 ms,282.38 us,1,bar
10.83 ms,22.389 us,1,usleep
339.287 us,3.107 us,2,foo
336.180 us,336.180 us,6,loop
""")

    def prepare(self):
        self.subcmd = 'record'
        self.option = '-F main'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '--format=csv'

    def sort(self, output):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for ln in output.split('\n'):
            if ln.strip() == '':
                continue
            line = ln.split(',')
            if line[0] == 'Total time':
                continue
            result.append('%s,%s' % (line[2], line[3]))

        return '\n'.join(result)
