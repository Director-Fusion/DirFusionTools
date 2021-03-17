#!/bin/bash

#WARNING - There is no logic flow to prompt users to ensure the passwords typed are correct. Type carefully.

# This is to reset your password on devices via ssh for a linux environment. This is to be coupled with a IPs.txt to take input from
# so the password can be reset. I have a 30 day password reset requirement. I run this on the last monday of each month. I keep the list of 
# IP addresses in the same directory as my script. Ctrl+C or Ctrl+Z to cancel. 

#First you enter in your current password.
#Second Enter your new password.

#IP list. CHANGE ME FOR YOUR NEEDS.
IPs="/home/dirfusion/Desktop/IPs.txt"

#User Name
echo -n "What is your user name?: "
read user

#First you enter in your current password.
#Second Enter your new password.

#Takes input for current password.
echo -n "Enter your current-password: "
read current

#Verifies typed password
echo "Your current password is: $current, is this correct?"
read -p "Press Enter to continue or Ctrl+C to cancel"

#Takes input for new password
echo -n "Enter your new-password: "
read new

#Verifies the new password
echo "Your new password is: $new, is this correct?"
read -p "Press Enter to continue or Ctrl+C to cancel..."

for IP in $(IPs)
do
  ssh -t $user@$IP passwd
  send "$current\r"
  send "$new\r"
  send "$new\r"
  send "exit\r"
done
