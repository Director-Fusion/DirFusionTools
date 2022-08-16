#!/bin/bash


while read line;
do
		dnsrecon -r $line -n 8.8.8.8 -d cat.com
done < "$@"

