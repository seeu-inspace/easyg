#!/bin/bash
for e in $(searchsploit $1 -w -t | grep http | cut -f 2 -d "|")
do
	exp_name=$(echo $e | cut -d "/" -f 5)
	url=$(echo $e | sed 's/exploits/raw/')
	wget -q --no-check-certificate $url -O $exp_name
done