#!/usr/bin/python

#
# pystrace -- Python tools for parsing and analysing strace output files
#
#
# Copyright 2012
#      The President and Fellows of Harvard College.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the University nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE UNIVERSITY AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE UNIVERSITY OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#
# Contributor(s):
#   Peter Macko (http://eecs.harvard.edu/~pmacko)
#

import getopt
import os.path
import sys
from jstack import *

from strace import *
from strace_utils import *
from datetime import datetime
import collections

#
# Convert to a .csv
#
def convert2csv(input_file, output_file=None, separator=',', quote='"'):
	'''
	Convert to a .csv
	
	Arguments:
	  input_file  - the input file, or None for standard input
	  output_file - the output file, or None for standard output
	  separator   - the separator
	'''

	# Open the files
	
	if input_file is not None:
		f_in = open(input_file, "r")
	else:
		f_in = sys.stdin
	
	if output_file is not None:
		f_out = open(output_file, "w")
	else:
		f_out = sys.stdout
	
	
	# Process the file
	
	strace_stream = StraceInputStream(f_in)
	first = True

	strace_dict = {}

	for entry in strace_stream:
		
		if first:
			first = False
			headers = ["TIMESTAMP", "SYSCALL", "CATEGORY", "SPLIT", \
					   "ARGC", "ARG1", "ARG2", "ARG3", "ARG4", "ARG5", "ARG6",
					   "RESULT", "ELAPSED"]
			if strace_stream.have_pids: headers.insert(0, "PID")
			# csv_write_row_array(f_out, headers, separator, "")
		
		# Print
		
		if entry.was_unfinished:
			i_was_unfinished = 1
		else:
			i_was_unfinished = 0
		
		data = [entry.timestamp, entry.syscall_name, entry.category,
			   i_was_unfinished,
			   len(entry.syscall_arguments),
			   array_safe_get(entry.syscall_arguments, 0),
			   array_safe_get(entry.syscall_arguments, 1),
			   array_safe_get(entry.syscall_arguments, 2),
			   array_safe_get(entry.syscall_arguments, 3),
			   array_safe_get(entry.syscall_arguments, 4),
			   array_safe_get(entry.syscall_arguments, 5),
			   entry.return_value,
			   entry.elapsed_time]
		if strace_stream.have_pids: data.insert(0, entry.pid)
		# csv_write_row_array(f_out, data, separator, quote)
		strace_dict[str(entry.timestamp)] = data


	# Close the files

	if f_out is not sys.stdout:
		f_out.close()
	strace_stream.close()
	return strace_dict


from subprocess import Popen, PIPE
DEVNULL = open(os.devnull, 'w')
def get_stack_trace_from_pid(pid):
    return Popen('jstack {pid}'.format(pid=pid), stdout=PIPE, stdin=DEVNULL, shell=True).communicate()[0]

def get_rss_from_pid(pid):
	return Popen('ps -o rss -p {pid}|sed -n 2p'.format(pid=pid), stdout=PIPE, stdin=DEVNULL, shell=True).communicate()[0]

#
# Print the usage information
#
def usage():
	sys.stderr.write('Usage: %s [OPTIONS] [FILE]\n\n'
		% os.path.basename(sys.argv[0]))
	sys.stderr.write('Options:\n')
	sys.stderr.write('  -h, --help         Print this help message and exit\n')
	sys.stderr.write('  -p, --help         Pid that strace should run on \n')
	sys.stderr.write('  -o, --output FILE  Print to file instead of the standard output\n')

def processJstack(pid):
	s_jstack_out = get_stack_trace_from_pid(pid)
	jstack= JStack(s_jstack_out)
	return jstack.parse()

def convertTimeStamp(timestamp):
	value = datetime.fromtimestamp(float(timestamp))
	return value.strftime('%Y-%m-%d %H:%M:%S')

# The main function
#
# Arguments:
#   argv - the list of command-line arguments, excluding the executable name
#
def main(argv):

	input_file = None
	output_file = None
	pid = None

	# Parse the command-line options

	try:
		options, remainder = getopt.gnu_getopt(argv, 'hop:',
			['help', 'output='])
		
		for opt, arg in options:
			if opt in ('-h', '--help'):
				usage()
				return
			elif opt in ('-o', '--output'):
				output_file = arg
			elif opt in ('-p', '--parent-pid'):
				pid = arg

		if len(remainder) > 1:
			raise Exception("Too many options")
		elif len(remainder) == 1:
			input_file = remainder[0]
	except Exception as e:
		sys.stderr.write("%s: %s\n" % (os.path.basename(sys.argv[0]), e))
		sys.exit(1)
	
	
	# Convert to .csv

	try:
		strace_data = convert2csv(input_file, output_file)
		jstack_data = processJstack(pid)
#rss_consumed = get_rss_from_pid(pid)
		combined_data = collections.OrderedDict()
		for timestamp, data in strace_data.items():
			hex_pid = hex(data[0])
			for j in jstack_data:
				if j['nid'] == hex_pid:
					if data[2] == "mmap":
						combined_data[timestamp] = [data[0], j['nid'], j['id'], "Mapped", data[12], data[7]]
					if data[2] == "munmap":
						for ct, cd in combined_data.items():
							if data[6] in cd and "Mapped" in cd:
								cd[3] = "UnMapped"

		headers = ["TIMESTAMP", "TASK_ID", "TASK_ID_HEX", "THREAD_NAME", \
				   "MAP_STATUS", "ADDRESS", "NUM_BYTES"]
		#print(headers)
		for k,v in combined_data.items():
#v.append(rss_consumed)
			print(convertTimeStamp(k), v)
	except IOError as e:
		sys.stderr.write("%s: %s\n" % (os.path.basename(sys.argv[0]), e))
		sys.exit(1)


#
# Entry point to the application
#
if __name__ == "__main__":
	main(sys.argv[1:])
