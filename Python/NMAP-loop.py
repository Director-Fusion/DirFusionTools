#!/usr/bin/python3

import subprocess

## This is to loop NMAP scans with created input text files. The idea is to increment the value of the text number to call the right file.

# Variables

text=input("Insert the number of the text file of the nmap IP file: ")


## Command 
out_bytes = subprocess.check_output(['sudo' + ' nmap' + ' -sC' + ' -sV' + ' -g' + ' 445' + ' -Pn' + ' -n ' + '--reason' + ' -p' + ' 66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3128,3306,4000,4001,4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8080,8888,30821' + ' -oA' + " /home/kali/Desktop/D7-Notes/Active/CAT/NMAP/137-230-" + text + ' -iL' + " /home/kali/Desktop/D7-Notes/Active/CAT/137-sub/137230-bl" + text + '.txt'])

# Running NMAP 

def nmap():
    while text <= 15:
        for a in text:
            try:
                out_bytes
                out_text = out_bytes.decode('utf-8')
                print(out_text)
            except subprocess.CalledProcessError as nmapexec:
                print("error code", nmapexec.returncode, nmapexec.output)
            text += 1
            print(text)
            
# Print output of loop


# Call function

nmap()

