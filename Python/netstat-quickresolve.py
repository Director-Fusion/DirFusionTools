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
<<<<<<< HEAD
    net = sp.check_output(['powershell.exe', 'Get-NetTCPConnection', '-state', 'ESTABLISHED', '|', 'format-list', '|', 'Select-String', '-Match' 'RemoteAddress', '|', 'Select-String', '-Pattern', "'\d+\.\d+\.\d+\.\d+'", '|', 'cut', '-d', "':'", '-f' '2', '|', 'Select-String', '-v', '127.0.0.1'])
=======
    net = sp.check_output(['powershell.exe', 'Get-NetTCPConnection', '-state', 'ESTABLISHED', '|', 'format-list', '|', 'Select-String', "'RemoteAddress'", '|', 'Select-String', '-Pattern', "'\d+\.\d+\.\d+\.\d+'", '|', 'cut', '-d', "':'", '-f' '2', '|', 'Select-String', '-NotMatch', '127.0.0.1'])
>>>>>>> e781ce7a2948e1b67ce63f1844428e95056d2ff4
    out_put = net.decode('utf-8').splitlines()
    #print(out_put)
    out_put = sorted(out_put)
    out_put = list(filter(None, out_put))
    print(out_put)
    
    for a in out_put:
        a = ip.IPv4Address(str(a))
        print(a)
        try:
            name = socket.gethostbyaddr(a)
            continue
        except:
            print("Error!")
        print(name)

resolve()