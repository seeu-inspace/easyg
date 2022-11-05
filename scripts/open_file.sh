#!/bin/bash
#Read a file in input line by line with
file=$1
while read -r line; do
    echo -e "$line"
done <$file 
