#!/bin/bash

# Define the search term as the first argument
search_term=$1

# Use searchsploit to search for exploits with the given term, and filter for http entries
exploit_list=$(searchsploit "$search_term" -w -t | grep http | cut -f 2 -d "|")

# Loop through each exploit in the list
for exploit in $exploit_list
do
    # Extract the exploit name and raw URL from the current entry
    exploit_name=$(echo "$exploit" | cut -d "/" -f 5)
    raw_url=$(echo "$exploit" | sed 's/exploits/raw/')

    # Download the exploit file using wget, with a quiet flag and no certificate check
    wget -q --no-check-certificate "$raw_url" -O "$exploit_name"
done
