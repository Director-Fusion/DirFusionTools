#!/bin/bash

while read line;
do
	 whois -b $line | grep 'inetnum:' | tee new-subs.txt
done < "$@"