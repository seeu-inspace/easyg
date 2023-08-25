#!/bin/bash

if [ -z "$GOPATH" ]; then
	echo "It looks like go is not installed, install it now and then rerun this script."
else
	go install -v github.com/OWASP/Amass/v3/...@master
	go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	go install -v github.com/gwen001/github-subdomains@latest
	go install -v github.com/OJ/gobuster/v3@latest
	go install -v github.com/tomnomnom/anew@latest
	go install -v github.com/tomnomnom/httprobe@latest
	go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
 	go install github.com/projectdiscovery/katana/cmd/katana@latest
  	go install github.com/jaeles-project/gospider@latest
   	go install github.com/hakluke/hakrawler@latest
fi
