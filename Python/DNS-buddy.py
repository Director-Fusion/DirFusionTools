#!/usr/bin/python3

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

# Header

header = ("""\
                                                                               
@@@@@@@   @@@  @@@   @@@@@@    @@@@@@@  @@@@@@@    @@@@@@   @@@  @@@  @@@ @@@  
@@@@@@@@  @@@@ @@@  @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@ @@@  @@@ @@@  
@@!  @@@  @@!@!@@@  !@@       !@@       @@!  @@@  @@!  @@@  @@!@!@@@  @@! !@@  
!@!  @!@  !@!!@!@!  !@!       !@!       !@!  @!@  !@!  @!@  !@!!@!@!  !@! @!!  
@!@  !@!  @!@ !!@!  !!@@!!    !@!       @!@!!@!   @!@  !@!  @!@ !!@!   !@!@!   
!@!  !!!  !@!  !!!   !!@!!!   !!!       !!@!@!    !@!  !!!  !@!  !!!    @!!!   
!!:  !!!  !!:  !!!       !:!  :!!       !!: :!!   !!:  !!!  !!:  !!!    !!:    
:!:  !:!  :!:  !:!      !:!   :!:       :!:  !:!  :!:  !:!  :!:  !:!    :!:    
 :::: ::   ::   ::  :::: ::    ::: :::  ::   :::  ::::: ::   ::   ::     ::    
:: :  :   ::    :   :: : :     :: :: :   :   : :   : :  :   ::    :      :     
                                                                               
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
        hostname=socket.gethostbyaddr(addresses)[0]
        print(hostname, addresses)
    except:
        print("Unresolvable IPv4 Address: ", addresses)
#IPv6   
#    try:
#        hostname=socket.gethostbyaddr(addresses)[0]
#        print(hostname, addresses)   
#    except:
#        print("Unresolvable IPv6 Address:: ", addresses)

### Gets fully qualified domain name from domain name. i.e "-d google.com"
def get_domainname():
    name = args.domain
    resolved=socket.getfqdn(name.rstrip())
    print(resolved, name.rstrip())

### Handles CIDR argument by resolving eahc address in the network. i.e "-c 10.0.0.0/24"
def ranges():
    cidr = ipaddress.ip_network(args.cidr, strict=False)
    for a in cidr:
        #IPv4
        try:
            hn = socket.gethostbyaddr(str(a))[0]
            print(hn, a)  
        except:    
            print("Unresolvable IPv4 Address:", a)
            continue
        #IPv6 
        #try:
        #    hn = socket.getaddrinfo(str(a, port=0, family=socket.AF_INET6, proto=socket.IPPROTO_TCP))
        #    print(hn, a)
        #except:    
        #    print("Unresolvable IPv6 Address:", a)

# Resolve requested data

## Figure out which argument is being used and execute the appropriate funciton
print(header)
if args.domain:
    get_domainname()
elif args.ip_address:
    get_hostname()
elif args.file:
    get_ip()
elif args.cidr:
    ranges()
else: 
    sys.exit()