#!/bin/bash 
clear
WHITE='\0033[1;37m'
echo -n -e ${WHITE}"Enter the IP of the domain controller to enumerate: "
read IP
nmap -Pn -T4 -sS -p139,445 --script=smb-enum-users $IP
bash -c "echo 'enumdomusers' | rpcclient $IP -U%"
bash -c "echo 'enumdomusers' | rpcclient $IP -U%" | cut -d[ -f2 | cut -d] -f1 > $IP-users.txt
