#!/bin/bash

set IPs = "$@"

for ip in IPs;
do
	sudo unicornscan -B 80 -H -s 198.51.44.3 -r50 $ip | tee  unicorn-out.txt
done