a#!/usr/bin/python3

"""
Author: DirectorFusion - directorfusion@directorfusion.us

DNS CRONY v.1.0
"""

import socket
import sys
import fileinput
import argparse 
from argparse import ArgumentParser
import ipaddress
import multiprocessing as mp

# Header

header = ("""                                                                               
    ____   _   _______  ______ ____   ____   _   __ __  __
   / __ \ / | / // ___// ____// __ \ / __ \ / | / / \ \/ /
  / / / //  |/ / \__ \/ /    / /_/ // / / //  |/ /   \  / 
 / /_/ // /|  /___/ // /__ // /_,_// /_/ //  /| /    / /  
/_____//_/ |_//____/\____/ /_/ |_| \____//_/ |_/    /_/                                                                                
""")

#Arguments Section

parser = argparse.ArgumentParser(description='Resolve DNS information')

parser.add_argument('-f', '--file', dest='file', metavar='FILE', required=False,
                    help='Text file to use for hostname or ip enumeration')
parser.add_argument('-d', '--domain', dest='domain', metavar='DOMAIN', required=False,
                    help='Domain servers to find')
parser.add_argument('-i', '--ip-address', dest='ip_address', metavar='IP ADDRESS v4/6',
                    required=False, help='Pass IP address information')
parser.add_argument("-c", "--cidr", dest='cidr', metavar='CIDR', required=False,
                    help='IP address range with CIDR notation')
parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                    help='verbose mode')
parser.add_argument('-o', '--output', dest='output', action='store_true',
                    help='Put output into a file')                    


#Functions

## Working with input

args = parser.parse_args()

## Convert hostname to IPv4/6

### Gets address or name from file of names/addresses. i.e "-f domains.txt"
#### Tested with a file called test.txt containing google.com, microsoft.com and yahoo.com.

def get_ip():
    subnets = open(args.file, "r")
    for subnet in subnets:    
    # IPv4
        try:
            address=socket.getaddrinfo(subnet.rstrip(), port=0, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
            print(subnet.rstrip(), address[0][4][0])
            continue
        except:
            print("subnet: ", subnet.rstrip(), "IPv4 Error")
    # IPv6
        try:    
            address=socket.getaddrinfo(subnet.rstrip(), port=0, family=socket.AF_INET6, proto=socket.IPPROTO_TCP)
            print(subnet.rstrip(), address[0][4][0])
            continue
        except:
            print("subnet: ", subnet.rstrip(), "IPv6 Error")

### Resolves hostname from individual IP address argument. i.e "-i 10.0.0.1"
def get_hostname():
    addresses = str(ipaddress.ip_address(args.ip_address))
#IPv4
    try:
        hostname=socket.getfqdn(addresses)
        resolved=socket.getfqdn(addresses.rstrip())
        print(hostname, addresses, resolved)
    except:
        print("Unresolvable IP Address: ", addresses)
#IPv6   
    try:
        hostname=socket.gethostbyaddr(addresses)[0]
        resolved=socket.getfqdn(addresses.rstrip())
        print(hostname, addresses, resolved)   
    except:
        print("Unresolvable IPv6 Address:: ", addresses)

### Gets fully qualified domain name from domain name. i.e "-d google.com"
def get_domainname():
    name = args.domain
    resolved=socket.getfqdn(name.rstrip())
    addr=socket.getaddrinfo(name, port=0, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
    print(resolved, addr[0][4][0], name.rstrip())
    addr=socket.getaddrinfo(name, port=0, family=socket.AF_INET6, proto=socket.IPPROTO_TCP)
    print(resolved, addr[0][4][0], name.rstrip())

### Handles CIDR argument by resolving eahc address in the network. i.e "-c 10.0.0.0/24"
def net():
    for a in ipaddress.ip_network(args.cidr, strict=False):
    #IPv4
        try:
            format(ipaddress.IPv4Address(a))
            hn = socket.gethostbyaddr(str(a))[0]
            print(hn, a)
            jobs.join()
            continue
        except:    
            print("Unresolvable IPv4 Address:", a)
    #IPv6 
        try:
            format(ipaddress.IPv6Address(a))
            hn = socket.gethostbyaddr(str(a))[0]
            print(hn, a)
            jobs.join()
        except:    
            print("Unresolvable IPv6 Address:", a)


# Resolve requested data

## Figure out which argument is being used and execute the appropriate funciton

def resolve():
    
    print(header)  
    num_threads = input("How many threads would you like: ")  
    if args.domain:
        get_domainname()
    elif args.ip_address:
        get_hostname()
    elif args.file:
        get_ip()
    elif args.cidr:
        net()
    else: 
        sys.exit()

resolve()

if __name__ == '__main__':
    # Threading/Multiprocessing
    resolve()

    for x in range(num_threads):
        jobs = mp.Process(target=net)
        jobs.start()
