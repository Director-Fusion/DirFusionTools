#!/usr/bin/python3

"""
Author: DirectorFusion - directorfusion@directorfusion.us

This is a tool that will perform DNS lookups and reverse dns lookups. 
The program will spit out CSV for the hostnames and associated IP addresses.
This aims to be Ipv4 and IPv6 usable, will also perform lookups from DNS sources
in random order to avoid too many searches. Not a guranteee. 

Eventually I want to turn it into an all in one tool. Long game for this is to have 
it pull DNS info from a argument for domain. Resolve IP to DNS or vice versa, do a 
reverse DNS lookup byt CIDR notation for IP 4 and 6 alike.
"""

import socket
import os
import sys
import fileinput
from argparse import ArgumentParser

#Variables Section

parser = argparse.ArgumentParser(desription='Resolve DNS information')

parser.add_argument('-f', '--file', dest='filename', metavar='FILE', required=False,
                    help='Text file to use for hostname or ip enumeration')

parser.add_argument('-d', '--domain', dest='domain', metavar='DOMAIN', required=True,
                    help='Domain servers to find')
parser.add_argument('-i', '--ip-address', dest='ip_address', metavar='ip_address',
                    required=False, help='Pass IP address information')
parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                    help='verbose mode')

args = parser.parse_args()

name = args.domain

ip_address = args.ip_address

#Functions

## Working with input

def reader(filename)
    hosts = open(filename)
    for host in hosts:
        host.readline()
    return hosts
    
## Convert hostname to IPv4/6

def get_ip(
    socket.gethostbyname(hosts)
)

def get_hostname(
    socket.gethostbyaddr(ip_address)
)

def get_domainname(
    socket.getfqdn(name)
)

# Resolve requested data

get_domainname


