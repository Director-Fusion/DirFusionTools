#!/bin.bash
# This puts open ports into a CSV format for reporting or running a service scan on ports. Idieally you ran a NMAP 
#scan and put an output as .txt. Change wildcard if more than one txt file is in the directory. 

cat *.txt | grep "open" | grep -v "filtered" | cut -d "/" -f 1 | sort -u | xargs | tr ' ' ',' > ports.txt


