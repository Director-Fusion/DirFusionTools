#!/bin/bash

# This requires the user to have at least user level credentials and a list of IP addresses.

cat ips.txt | while read line
do
    echo $line && rpcclient -U "<domain>\<username>%<password>" -c "enumdomusers;quit" $line
done