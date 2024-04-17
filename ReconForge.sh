#!/bin/bash

RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

figlet  -c "ReconForge" | lolcat
echo ""
echo -e "${CYAN}                                             Coded by : Bēñēfáctör ${NC}"
echo ""

# ----------------------------------------------------------- FILE INPUT ----------------------------------------------------------- #

echo -e "${RED}[+] Please save your in-scope domains in .txt file and enter file path : ${NC}"
read target_file

if [ -f "$target_file" ]; then
    if [[ $target_file != *.txt ]]; then
    echo "Error: The file must be a .txt file."
    exit 1
    fi
else
    echo "The file '$target_file' does not exist."
    exit 1
fi

# ----------------------------------------------------------- CONFIG QUESTIONS ----------------------------------------------------------- #

echo -e "${RED}[+] Welcome, please give answers to below questions in y or n to configure full scan : ${NC}"

echo -e "${GREEN}[?] Do you want to perform WAF detection?{NC}"
read -p "Enter y or n: " response1
echo -e "{GREEN}[?] Do you want to perform port scanning?{NC}"
read -p "Enter y or n: " response2
echo -e "{GREEN}[?] Do you want to discover directories of all subdomains?{NC}"
read -p "Enter y or n: " response3
if [ "$response3" = "y" ]; then
    echo -e "{GREEN}[?] Do you want to use a custom wordlist for Dirsearch?{NC}"
    read -p "Enter y or n: " response4
    if [ "$response4" = "y" ]; then
        read -p "Enter the path of wordlist: " dir_wordlist
    fi
fi
echo -e "{GREEN}[?] Do you want to perform crawling for endpoints?{NC}"
read -p "Enter y or n: " response5
echo -e "{GREEN}[?] Do you want to look for hidden APIs in js files?{NC}"
read -p "Enter y or n: " response6
echo -e "{GREEN}[?] Do you want to initiate vulnerability scan using Nuclei?{NC}"
read -p "Enter y or n: " response7
if [ "$response7" = "y" ]; then
    echo -e "{GREEN}[?] Do you want to use a custom templates for Nuclei?{NC}"
    read -p "Enter y or n: " response8
    if [ "$response8" = "y" ]; then
        read -p "Enter the path of wordlist: " nuclei_wordlist
    fi
fi
echo -e "{GREEN}[?] Do you want to initiate XSS vuln scan using Dalfox?{NC}"
read -p "Enter y or n: " response9
if [ "$response9" = "y" ]; then
    echo -e "{GREEN}[?] Do you want to use a custom payloads for Dalfox?{NC}"
    read -p "Enter y or n: " response10
    if [ "$response10" = "y" ]; then
        read -p "Enter the path of payloads: " dalfox_wordlist
    fi
fi
echo -e "{GREEN}[?] Do you want to perform OSINT using theHarvester?{NC}"
read -p "Enter y or n: " response11
if [ "$response11" = "y" ]; then
    echo -e "${YELLOW}[:-:] Enter main domain to search for : ${NC}"
    read search_for
fi

echo -e "${RED}[+] Thanks for configuring your scan, Now sit back and relax!! ${NC}"

# ----------------------------------------------------------- SUBDOMAIN ENUMERATION ----------------------------------------------------------- #

echo -e "${RED}[+] Starting Recon with enumerating subdomains...${NC}"

echo -e "${YELLOW}[:-:] Gathering subdomains from Amass...${NC}"
amass enum -passive -df $target_file -o subs.txt

echo -e "${YELLOW}[:-:] Gathering subdomains from Subfinder...${NC}"
subfinder -dL $target_file -all -recursive | anew subs.txt

echo -e "${YELLOW}[:-:] Gathering subdomains from Crt.sh ...${NC}"
while IFS= read -r domain; do
    echo "Checking subdomains for $domain..."
    curl "https://crt.sh/?q=$domain" | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | grep -E "\.$domain$" | anew subs.txt
done < "$target_file"

cat subs.txt | sort -u > subdomains.txt
rm subs.txt

echo -e "${YELLOW}[:-:] Saving all subdomains in subdomains.txt${NC}"

echo -e "${RED}[+] Checking for live subdomains...${NC}"

echo -e "${YELLOW}[:-:] Running Httpx...${NC}"
cat subdomains.txt | httpx -sc -ct -title -location -o alive-subs_with-details.txt
cat alive-subs_with-details.txt | cut -d' ' -f1 | sed 's/https:\/\///' | sed 's/http:\/\///' | anew alive-subs.txt

echo -e "${YELLOW}[:-:] Saving two files; one with only live sudomains ( alive-subs.txt ) and second with some additional details also ( alive-subs_with-details.txt )${NC}"

# ----------------------------------------------------------- WAF DETECTION ----------------------------------------------------------- #

if [ "$response1" = "y" ]; then
    echo -e "${RED}[+] Initiating WAF Detection using wafw00f...${NC}"
    wafw00f -a -i alive-subs.txt -o waf.txt
    echo -e "${YELLOW}[:-:] WAF scanning done and results are stored in waf.txt ${NC}"
fi

# ----------------------------------------------------------- PORT SCANNING ----------------------------------------------------------- #

if [ "$response2" = "y" ]; then
    echo -e "${RED}[+] Initiating Port Scans using Naabu...${NC}"
    naabu -list alive-subs.txt -c 50 -nmap-cli 'nmap -sV -sC -A' -o naabu-report.txt
    echo -e "${YELLOW}[:-:] Scans are saved in naabu-report.txt${NC}"
fi

# ----------------------------------------------------------- DIRECTORY FUZZING ----------------------------------------------------------- #


if [ "$response4" = "y" ]; then
    echo -e "${RED}[+] Fuzzing for directories using Dirsearch...${NC}"
    dirsearch -l alive-subs.txt -x 500,502,429,404,400 -R 5 --random-agent -t 100 -F -o directories.txt -w $dir_wordlist
elif [ "$response4" = "n" ]; then
    echo -e "${RED}[+] Fuzzing for directories using Dirsearch...${NC}"
    dirsearch -l alive-subs.txt -x 500,502,429,404,400 -R 5 --random-agent -t 100 -F -o directories.txt
fi
echo -e "${YELLOW}[:-:] Results are saved in directories.txt${NC}"

# ----------------------------------------------------------- ENDPOINT CRAWLING ----------------------------------------------------------- #

if [ "$response5" = "y" ]; then
    echo -e "${RED}[+] Initiating Crawls${NC}"
    echo -e "${YELLOW}[:-:] Using Katana for crawls${NC}"
    cat alive-subs.txt | katana | anew urls.txt
    echo -e "${YELLOW}[:-:] Using GAU for crawls${NC}"
    cat alive-subs.txt | gau | anew urls.txt
    echo -e "${YELLOW}[:-:] Filtering URLs${NC}"
    cat urls.txt | uro >> endpoints.txt
    echo -e "${YELLOW}[:-:] Results are saved in endpoints.txt${NC}"
fi

# ----------------------------------------------------------- HIDDEN APIs ----------------------------------------------------------- #

if [ "$response6" = "y" ]; then
    echo -e "${RED}[+] Initiating Hidden API search using Secret Finder...${NC}"
    read -p "Enter file path of SecretFinder.py : " secret_path
    cat endpoints.txt | grep ".js$" | uro | anew js.txt
    cat js.txt | while read url; do python3 $secret_path -i $url -o cli >> secret_apis.txt; done
    rm js.txt
    echo -e "${YELLOW}[:-:] Results are saved in secret_apis.txt${NC}"
fi

# ----------------------------------------------------------- FILTERING ENDPOINTS ----------------------------------------------------------- #

echo -e "${RED}[+] Filtering endpoints to remove unnecessary file urls...${NC}"
cat endpoints.txt | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | anew params.txt
echo -e "${YELLOW}[:-:] Final parameters are saved in params.txt${NC}"

# ----------------------------------------------------------- NUCLEI SCAN ----------------------------------------------------------- #

if [ "$response8" = "y" ]; then
    echo -e "${RED}[+] Scanning for vulnerabilities using Nuclei...${NC}"
    nuclei -list params.txt -c 70 -rl 200 -fhr -lfa -t $nuclei_wordlist -o nuclei-report.txt -es info
elif [ "$response8" = "n" ]; then
    echo -e "${RED}[+] Scanning for vulnerabilities using Nuclei...${NC}"
    nuclei -list params.txt -c 70 -rl 200 -fhr -lfa -o nuclei-report.txt -es info
fi
echo -e "${YELLOW}[:-:] Results are saved in nuclei-report.txt${NC}"

# ----------------------------------------------------------- DALFOX SCAN ----------------------------------------------------------- #

if [ "$response10" = "y" ]; then
    echo -e "${RED}[+] Scanning for vulnerabilities using Dalfox...${NC}"
    dalfox file params.txt --custom-payload $dalfox_wordlist -o dalfox-results.txt
elif [ "$response10" = "n" ]; then
    echo -e "${RED}[+] Scanning for vulnerabilities using Dalfox...${NC}"
    dalfox file params.txt -o dalfox-results.txt
fi
echo -e "${YELLOW}[:-:] Results are saved in dalfox-results.txt${NC}"

# ----------------------------------------------------------- OSINT ----------------------------------------------------------- #

if [ "$response11" = "y" ]; then
    echo -e "${RED}[+] Initiating OSINT Scans using theHarvester...${NC}"
    theHarvester -d $search_for -s -b all -f OSINT
    echo -e "${YELLOW}[:-:] Scans are saved in OSINT.json and OSINT.xml${NC}"
fi

# ----------------------------------------------------------- THE END! ----------------------------------------------------------- #

#####################################################################################################################################
############################################## Hope this helped you, Thanks for using! ##############################################
######################################################## (:Happy Hacking:) ##########################################################
#####################################################################################################################################
