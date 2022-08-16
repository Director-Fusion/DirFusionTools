#!/bin/bash
#This script takes hostname input from domains.txt and performs a curl command to get the HTTP response 200, 301, 403,50X etc...

for protocol in 'http://' 'https://'; do
		while read line;
		do
				code=$(curl -L --write-out "%{http_code}\n" --output /dev/null --silent --insecure $protocol$line)
		if [ $code = "000" ]; then
			echo "$protocol$line: not responding."
		else
			echo "$protocol$line: HTTP $code"
			echo "$protocol$line: $code" >> alive.txt
		fi	
		done < domains.txt
done