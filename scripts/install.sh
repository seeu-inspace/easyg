#!/bin/bash

# Check if the script is executed with root privileges
if [ "${UID}" -eq 0 ]
then
    echo ""; echo -e "\e[32m\e[1mStarting the installation of the tools.\e[0m\e[39m"; echo "";
else
    echo ""; echo -e "\e[91m\e[1mRoot privileges are required\e[0m\e[39m"; echo "";
    exit
fi

# update
sudo -- sh -c "apt -y update && apt -y upgrade && apt -y autoremove"

# python, ruby and some packages
apt-get install -y python python-pip python3 python3-pip python-dnspython python-dev python-setuptools virtualenv unzip make gcc libpcap-dev curl build-essential libcurl4-openssl-dev libldns-dev libssl-dev libffi-dev libxml2 jq libxml2-dev libxslt1-dev build-essential ruby-dev ruby-full libgmp-dev zlib1g-dev xargs git rename findutils terminator chromium-browser tmux awscli neo4j bloodhound

# ruby's gems
gem install uri net-http json socket webdrivers selenium-webdriver

# go and some tools
if [ -z "$GOPATH" ]; then
	echo "It looks like go is not installed, install it now and then rerun this script."
	#---------Install Golang
	echo -e "\e[93m\e[1m----> Golang environment installation in progress ...";
	cd /tmp && wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz > /dev/null 2>&1 && tar xvf go1.21.0.linux-amd64.tar.gz > /dev/null 2>&1;
	mv go /usr/local
	export GOROOT=/usr/local/go && export GOPATH=$HOME/go && export PATH=$GOPATH/bin:$GOROOT/bin:$PATH;
	echo 'export GOROOT=/usr/local/go' >> ~/.bash_profile && echo 'export GOPATH=$HOME/go'	>> ~/.bash_profile	&& echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bash_profile;
	source ~/.bash_profile
	echo -e "\e[32mGolang environment installation is done !"; echo "";
	sleep 1.5
else
	go install -v github.com/OWASP/Amass/v3/...@master
	go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	go install -v github.com/gwen001/github-subdomains@latest
	go install -v github.com/OJ/gobuster/v3@latest
	go install -v github.com/tomnomnom/anew@latest
	go install -v github.com/tomnomnom/httprobe@latest
	go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
 	go install -v github.com/projectdiscovery/katana/cmd/katana@latest
  	go install -v github.com/jaeles-project/gospider@latest
   	go install -v github.com/hakluke/hakrawler@latest
fi

# update
sudo -- sh -c "apt -y update && apt -y upgrade && apt -y autoremove"
