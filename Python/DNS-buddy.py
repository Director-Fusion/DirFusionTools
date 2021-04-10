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
import argparse 
from argparse import ArgumentParser
import ipaddress

#Variables Section

parser = argparse.ArgumentParser(description='Resolve DNS information')

parser.add_argument('-f', '--file', dest='file', metavar='FILE', required=False,
                    help='Text file to use for hostname or ip enumeration')
parser.add_argument('-d', '--domain', dest='domain', metavar='DOMAIN', required=False,
                    help='Domain servers to find')
parser.add_argument('-i', '--ip-address', dest='ip_address', metavar='ip_address',
                    required=False, help='Pass IP address information')
parser.add_argument("-c", "--cidr", dest='cidr', metavar='CIDR', required=False,
                    help='IP address range with CIDR notation')
parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                    help='verbose mode')



#Functions

"""
print("file {} domain {} ip_address {} ".format(
       args.file,
       args.domain,
       args.ip_address  
       ))
"""

## Working with input

args = parser.parse_args()

#subnet = open(args.file, "r")

name = args.domain

#addresses = str(ipaddress.ip_address(args.ip_address))

cidr = ipaddress.ip_network(args.cidr, strict=False)

## Convert hostname to IPv4/6
"""
def get_ip():
    for subnet in subnets:

        #print("current line: ", subnet.rstrip())
    # IPv4
        address=socket.getaddrinfo(subnet.rstrip(), port=0, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
        print(subnet.rstrip(), address[0][4][0])
       
    # IPv6
        try:    
            address=socket.getaddrinfo(subnet.rstrip(), port=0, family=socket.AF_INET6, proto=socket.IPPROTO_TCP)
            print(subnet.rstrip(), address[0][4][0])
            continue
        except:
           print("subnet: ", subnet.rstrip(), "IPv6 Error")

def get_hostname():
    
    #IPv4
    try:
        hostname=socket.gethostbyaddr(addresses)[0]
        print(hostname, addresses)
    except:
        print("IPv4 Unresolvable Address: ", address)

    # IPv6   
    try:
        hostname=socket.gethostbyaddr(addresses)[0]
        print(hostname, addresses)   
    except:
        print("IPv6 Unresolvable Address: ", address)

def get_domainname():
    for subnet in subnets:
        resolved=socket.getfqdn(host.rstrip())
        print(resolved)
"""

def ranges():
    for a in cidr:
        #IPv4
        try:
            print(a)
            hn = socket.gethostbyaddr(a)#, port=0, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
            print(hn)
        except:
            print("Unresolvable IPv4 Address:", a)
      
        #IPv6
        try:   
            print(a)
            hn = socket.gethostbyaddr(a)#, port=0, family=socket.AF_INET6, proto=socket.IPPROTO_TCP)
            print(hn)
        except:
            print("Unresolvable IPv6 Address:", a)

# Resolve requested data

#get_domainname()
#get_hostname()
#get_ip()
ranges()
