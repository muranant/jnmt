#!/usr/bin/python
#
# A Poor's Man Profiler for java applications
#
# GPLv3 (c) Babel srl
#
# Author: Roberto Polli <rpolli@babel.it>
#
import re
import sys
import getopt
import time
from subprocess import Popen, PIPE

verbose = False


def dprint(s):
    global verbose
    if verbose:
        print(s)




class JStack(object):

    # jstack states, see http://docs.oracle.com/javase/1.5.0/docs/api/java/lang/Thread.State.html
    STATES = ('NEW', 'BLOCKED', 'TERMINATED', 'RUNNABLE', 'WAITING',
              'TIMED_WAITING')

    class AlreadyParsedError(Exception):
        pass

    def __init__(self, s_stack):
        """initialize jstack with the output of jstack command"""
        self.output = s_stack
        self.threads = []
        self.state_tot = dict(zip(JStack.STATES, [0 for x in JStack.STATES]))
        self.parsed = False

        # finally parse
        # self.parse()

    def parse(self):
        """Parse jstack command output.

            Infos are gathered into a jstack object that handles some stats
        """
        if self.parsed:
            raise JStack.AlreadyParsedError

        class en_thread(object):
            pass

        # regular expressions for parsing
        sre_class = r'[A-z][A-z0-9.]+[A-z]'
        re_thread = re.compile(r'\"(.+?)\".*prio=([0-9]+) tid=(0x[0-9a-f]+) nid=(0x[0-9a-f]+)')
        # re_thread = re.compile(r'^"([^\"]+)"\s+(daemon )?prio=([0-9]+) tid=(0x[0-9a-f]+) nid=(0x[0-9a-f]+) ')
        (en_thread.TID, en_thread.PRIO, en_thread.ADDR, en_thread.NID) = range(1, 5)
        re_trace = re.compile(r'^\s+at (' + sre_class + ')\(([^ ]+)\)')
        re_trace = re.compile(r'^\s+at (.+)$')
        re_state = re.compile(r'^\s+java.lang.Thread.State: ([^ ]+)')

        # to enable testing, I need to parse
        #    even a single string
        reader = self.output
        if isinstance(self.output, str):
            reader = self.output.splitlines()

        # trace    points to a dict() inside the current java thread
        #    and is used to store the backtrace of the current thread
        thread = None
        for line in reader:
            line = line.rstrip()
            dprint("line: [%s]" % line)
            m_thread = re_thread.match(line)
            m_trace = re_trace.match(line)
            m_state = re_state.match(line)

            if m_thread:
                dprint("\t thread:[%s]" % m_thread.group(en_thread.TID))
                thread = { 'id': m_thread.group(en_thread.TID),
                          'nid': m_thread.group(en_thread.NID),
                           'addr': m_thread.group(en_thread.ADDR),
                          'trace': dict(),
                          'state': None}
                self.threads.append(thread)

            elif thread and m_state:
                dprint("\t state: %s" % m_state.group(1))
                state = m_state.group(1)
                thread['state'] = state
                self.state_tot[state] += 1
                dprint("\t state_tot[%s]: %d" % (state, self.state_tot[state]))

            elif thread and m_trace:
                """update trace until it points to another thread"""
                assert thread['trace'] is not None
                dprint("\t trace: [%s]" % m_trace.group(1))
                thread['trace'].setdefault(m_trace.group(1), 0)
                thread['trace'][m_trace.group(1)] += 1
                dprint("trace %s" % thread['trace'])

        dprint("threads: %s" % self.threads)
        self.parsed = True
        return self.threads



    def wchan(self):
        """ reverse map of wait channel and threads.

            eg. {
            methodA: [thread1,.., threadN], # thread blocked on methodA
                }
        """
        chans = dict()
        for x in self.threads:
            wc = x['wchan']
            chans.setdefault(wc, [])
            chans[wc].append(x['sock'])

        dprint("wchan: %s" % chans)
        return chans

    def joint(self, state=None, sock=None):
        """ print_summary of all methods count.

            eg. {
            methodA: 123,
            methodB: 35,
                }
        """
        dprint("joint. state: %s, sock: %s" % (state, sock))

        assert self.threads
        if state:
            assert state in JStack.STATES

        traces = dict()
        for t in self.threads:
            # eventually filter by state
            if state and t['state'] != state:
                continue
            if sock and (t['sock'].find(sock) == -1):
                continue
            else:
                dprint("joint: checking sock: %s" % t['sock'])

            for (c, v) in t['trace'].iteritems():
                traces.setdefault(c, 0)
                traces[c] += v

        return traces

    def print_summary(self, limit=0, threshold=0):
        print("Total threads: %d\n" % len(self.threads))
        for s in self.state_tot.iteritems():
            print("\tstate: %-15s %10d" % s)

        for (chan, threads) in self.wchan().iteritems():
            print("\twchan: %s for %d threads" % (chan, len(threads)))

        trace_count = self.joint()
        dprint("\ntrace_count: %s" % trace_count)
        JStack.print_summary_trace(
            trace_count, limit=limit, threshold=threshold)

    def csv(self):
        print("%5d " % len(self.threads))
        for s in JStack.STATES:
            print("%5d " % self.state_tot[s],)

    @staticmethod
    def print_summary_trace(trace_count, limit=0, threshold=0):
        """Prints the trace counter, that should be a list of vectors"""
        assert isinstance(trace_count, dict) == True
        print("Most frequent calls (limit: %d, threshold: %s):" % (limit, threshold))
        if limit == 0:
            limit -= 1
        dprint("\ntrace_count: %s" % trace_count)
        for tc in sorted(trace_count.iteritems(), key=lambda x: x[1], reverse=True):
            if limit == 0:
                break
            if tc[1] < threshold:
                break

            print("\t%-120s %5d" % tc)
            limit -= 1

    @staticmethod
    def sum(tot, stack_new, state=None, sock=None):
        """Return a dictionary with thread counters."""
        dprint("Summing jstats: state:%s,sock:%s" % (state, sock))
        threads_tot = dict()
        thread_union = [x for x in tot.iteritems()]
        thread_union.extend(
            [x for x in stack_new.joint(state=state, sock=sock).iteritems()])
        dprint("thread_union: %s" % thread_union)
        for (k, v) in thread_union:
            dprint("k: %s" % k)
            threads_tot.setdefault(k, 0)
            threads_tot[k] += v
        return threads_tot


# run_jstack(sys.argv[1:])
