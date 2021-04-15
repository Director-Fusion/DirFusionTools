#!/usr/bin/python

# By: Cory Keller/DirectorFusion directorfusion@directorfusion.us
# This is a program to run netstat and resolve all established connections to the IP address's hostname

import subprocess as sp
import socket
import ipaddress as ip
import fileinput
import re

def resolve():
    # Net is a powershell equivalent of netstat finding established connections and filtering out the ipv4 addresses.
    net = sp.check_output(['powershell.exe', 'Get-NetTCPConnection', '-state', 'ESTABLISHED', '|', 'format-list', '|', 'grep', "'RemoteAddress'", '|', 'Select-String', '-Pattern', "'\d+\.\d+\.\d+\.\d+'", '|', 'cut', '-d', "':'", '-f' '2', '|', 'grep', '-v', '127.0.0.1'])

    out_put = net.decode('utf-8')

    #print(out_put)
    regex = r"(\d+\.\d+\.\d+\.\d+)"
    addresses = re.finditer(regex, out_put, re.MULTILINE)
    for address in addresses:
        print(address)
    """    for match in match:
            match = ip.IPv4Address(str(i))
            name = socket.gethostbyaddr(match)
            print(match)
"""
resolve()