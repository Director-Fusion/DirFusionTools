#!/bin/bash

while read line;
do
	ffuf -w /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt -u https://FUZZ.$line -of csv -o $line.csv

done < "$@"	
