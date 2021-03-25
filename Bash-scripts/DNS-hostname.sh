#!/bin/bash

# This script will run an nslookup lookup through all potential hosts in a /24 subnet.

for /L %i in (1,1,255) do @nslookup 10.10.10.%i <server ip to resolve from> 2>nul | find "Name" && echo 10.10.10.%i