#!/bin/bash

# Make sure you run this file with sudo

# sudo ./install.sh

sudo apt-get install python3
sudo apt install golang-go
sudo apt install figlet lolcat
go install -v github.com/owasp-amass/amass/v3/...@master
sudo apt install subfinder
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo apt install wafw00f
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/tomnomnom/anew@latest
sudo apt install dirsearch
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
pip3 install uro
apt install nuclei
pip install theHarvester
go install github.com/hahwul/dalfox/v2@latest

# If any tool is left, plz search on google and install by yourself.
