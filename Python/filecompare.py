#!/usr/bin/env python3

import fileinput
import argparse

parser = argparse.ArgumentParser(description='Resolve DNS information')

parser.add_argument('-f', '--file', dest='file', metavar='FILE', required=True,
                    help='Text file to test with')

parser.add_argument('-e', '--enum', dest='enum', metavar='ENUM', required=True,
					help='Text file to enumerate',)

parser.add_argument('-d', '--delim', dest='delim', metavar='DELIM', required=True,
					help='Delimeter in files, ";,:,#, or comma are common delimeters.')

#Functions

## Working with input

args = parser.parse_args()

file1 = open(args.enum, "r")
file2 = open(args.file, "r")
d = args.delim

for e in file1:
	cws = e.strip().split(":")[1]
	e = e.split(d)[0]
	
	for p in file2:
		passwords = p.strip().split(":")[1]
		p = p.split(d)[0]
	
		if e == p:
			if passwords != "":
				print(cws + ":" + passwords)
	file2.seek(0)