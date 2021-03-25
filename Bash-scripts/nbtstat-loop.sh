#!/bin/bash

# Loop nbtstat -A to enumerate remote machines

for /L %i in (1,1,255) do nbtstat -A 10.10.10.%i 2>nul && echo 10.10.10.%i 