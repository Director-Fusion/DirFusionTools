#!/bin/bash

# This tool is meant to cat out all text documents in a given directory and loop through each time to see if a
# part in a subdomain exsits or not inside of those dictionarys

while read domain;
do
	cat *.txt | grep -rn -e '$domain'
done < "$@"

