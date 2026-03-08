#!/usr/bin/env python3

# When using 'uftrace dump --chrome --time-range T1~T2', functions that were
# active at range_stop (i.e. they entered within the range but exit after T2)
# must produce synthetic E events at T2 so that every B event has a matching E.
#
# This test records the abc call chain (main -> a -> b -> c -> getpid), then
# dumps with --chrome using a time range that starts at c's entry and stops at
# getpid's entry.  Since getpid (and all outer functions) exit after T2, the
# chrome dump must emit synthetic E events for them at range_stop.

import subprocess as sp

from runtest import TestBase

START = '0'
STOP = '1'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
{"traceEvents":[
{"ts":0,"ph":"M","pid":1,"name":"process_name","args":{"name":"[1] t-abc"}},
{"ts":0,"ph":"M","pid":1,"name":"thread_name","args":{"name":"[1] t-abc"}},
{"ts":0,"ph":"B","pid":1,"name":"main"},
{"ts":0,"ph":"B","pid":1,"name":"a"},
{"ts":0,"ph":"B","pid":1,"name":"b"},
{"ts":0,"ph":"B","pid":1,"name":"c"},
{"ts":0,"ph":"B","pid":1,"name":"getpid"},
{"ts":0,"ph":"E","pid":1,"name":"getpid"},
{"ts":0,"ph":"E","pid":1,"name":"c"},
{"ts":0,"ph":"E","pid":1,"name":"b"},
{"ts":0,"ph":"E","pid":1,"name":"a"},
{"ts":0,"ph":"E","pid":1,"name":"main"}
]}
""", sort='chrome')

    def prerun(self, timeout):
        global START, STOP

        self.subcmd = 'record'
        record_cmd = self.runcmd()
        sp.call(record_cmd.split())

        # Find entry timestamps of 'c' (START) and 'getpid' (STOP).
        # With --time-range START~STOP, main/a/b need synthetic B events at
        # START (they entered before START), getpid gets a natural B at STOP,
        # and all functions (getpid, c, b, a, main) exit after STOP so they
        # need synthetic E events at STOP from the remaining-functions loop.
        self.subcmd = 'replay'
        self.option = '-f time -F main'
        replay_cmd = self.runcmd()

        p = sp.Popen(replay_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        r = p.communicate()[0].decode(errors='ignore')
        lines = r.split('\n')
        if len(lines) < 6:
            return TestBase.TEST_DIFF_RESULT
        START = lines[4].split()[0]  # skip header, main, a, b (= 4 lines)
        STOP = lines[5].split()[0]   # getpid entry timestamp
        p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'dump'
        self.option = '--chrome -r %s~%s' % (START, STOP)
