#!/usr/bin/env python3

import argparse
import os

# This is to run nikto off a input file.  Created to educate myself and solve a problem I know nikto accepts gnmap file input.

# Arguments
parser = argparse.ArgumentParser(description='Add input as text file.')
parser.add_argument('-f', '--file', dest='file', metavar='FILE', required=False, help='Text file(.txt) to use as input for nikto scanning')
args = parser.parse_args()

# Input File
hosts = open(args.file, "r")

# OutPut file
#outfile = write('Nikto results:')

for host in hosts:
	os.system('nikto -host https://' + host) # + '-output ' + outfile)
	
exit()