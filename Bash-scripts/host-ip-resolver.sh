#!/bin/bash
#By: Cory Keller | Cyber Defense Labs

while read line;
do
	address="$(host -t A $line 8.8.8.8 | awk '/has.*address/{print $NF; exit}')"
	echo "$line $address"
done < "$@"
