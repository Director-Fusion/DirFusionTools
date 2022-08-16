#!/usr/bin/python3

# Takes IP range i.e ("192.168.0.0-192.168.0.255")

import fileinput
from cidrize import cidrize

#range = input("Input: ")
range = open("new-subs.txt")

def list():
    for c in range:
        a = cidrize(c)[0]
        print(a)

#CAll Function
list() 