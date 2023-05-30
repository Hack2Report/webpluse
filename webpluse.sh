#!/bin/bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No color

# About me
echo -e "${GREEN}WebPulse tool developed by ${RED}Chandram ${GREEN}member of Hack2Report team.${NC}"
echo -e "${GREEN}WebPulse checks port 80-http and 443-https protocols ${GREEN}${NC}"
echo ""

# Check if target IP address is provided
if [ -z "$1" ]
then
    read -p "Enter target IP or hostname: " target
else
    target=$1
fi

# Port 80 HTTP code starts here

echo ""
echo -e "${YELLOW}WebPulse Checking IP localtion and Info${RED} $target for port 80 ${NC}"
echo ""
curl -s ipinfo.io/$target

echo ""
echo -e "${YELLOW}WebPulse Checking vulners and Service version${RED} $target for port 80 ${NC}"
echo ""
nmap -sV -sC --script vulners -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse Checking virtual hostnames related information${RED} $target for port 80 ${NC}"
echo ""
nmap --script http-vhosts -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse Checking HEAD request for the root folder${RED} $target for port 80 ${NC}"
echo ""
nmap -sV --script=http-headers -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse Checking potentially risky methods${RED} $target for port 80 ${NC}"
echo ""
nmap --script http-methods -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse Checking HTTP response headers related to security${RED} $target for port 80 ${NC}"
echo ""
nmap --script http-security-headers -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse attempts to exploit the "shellshock" vulnerability${RED} $target for port 80 ${NC}"
echo ""
nmap -sV --script http-shellshock -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse checking Slowloris DoS attack without actually launching a DoS attack${RED} $target for port 80 ${NC}"
echo ""
nmap --script http-slowloris-check -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse checking SQL injection attack${RED} $target for port 80 ${NC}"
echo ""
nmap -sV --script=http-sql-injection -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse checking XSS vulnerability${RED} $target for port 80 ${NC}"
echo ""
nmap --script http-stored-xss.nse -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse checking XSubversion repository by examining logs${RED} $target for port 80 ${NC}"
echo ""
nmap --script http-svn-enum -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse checking Requests information from a Subversion repo${RED} $target for port 80 ${NC}"
echo ""
nmap --script http-svn-info -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse determining whether a web server is protected by an IPS, IDS or WAF${RED} $target for port 80 ${NC}"
echo ""
nmap --script http-waf-detect -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse searching the xssed.com database${RED} $target for port 80 ${NC}"
echo ""
nmap --script http-xssed.nse -Pn -T4 -p80 $target

echo ""
echo -e "${YELLOW}WebPulse tries to detect web application firewall & its type/version${RED} $target for port 80 ${NC}"
echo ""
nmap --script=http-waf-fingerprint -Pn -T4 -p80 $target
echo ""

echo -e "${YELLOW}WebPulse enumerates directories used by popular web applications${RED} $target for port 80 ${NC}"
echo -e "${RED}This task will take a while, so have some coffee${NC}"
echo ""
nmap -sV --script=http-enum -Pn -T4 -p80 $target
echo ""

echo -e "${YELLOW}WebPulse running some open CVE check${RED} $target for port 80 ${NC}"
echo -e "${RED}This task will take a while, so have some coffee${NC}"
echo ""
echo -e "${RED}This task will take a while, so have some coffee${NC}"
nmap --script http-vmware-path-vuln,http-vuln-cve2006-3392,http-vuln-cve2010-2861,http-vuln-cve2011-3192.nse,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-vuln-cve2013-6786,http-vuln-cve2013-7091,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1427,http-vuln-cve2015-1635.nse,http-vuln-cve2017-1001000,http-vuln-cve2017-5638,http-vuln-cve2017-8917,http-vuln-wnr1000-creds -Pn -T4 -p80 $target

echo -e "${YELLOW}WebPulse performs bruteforce password auditing against Wordpress CMS/blog${RED} $target for port 80 ${NC}"
echo ""
nmap -sV --script http-wordpress-brute -Pn -T4 -p80 $target
echo ""

echo -e "${YELLOW}WebPulse enumerates themes & plugins of Wordpress installations${RED} $target for port 80 ${NC}"
echo ""
nmap -sV --script http-wordpress-brute -Pn -T4 -p80 $target
echo ""

echo -e "${YELLOW}WebPulse Enumerates usernames in Wordpress blog/CMS${RED} $target for port 80 ${NC}"
echo ""
nmap -sV --script http-wordpress-brute -Pn -T4 -p80 $target
echo ""

echo -e "${YELLOW}WebPulse Tests for access with default credentials${RED} $target for port 80 ${NC}"
echo ""
nmap --script http-default-accounts -Pn -T4 -p80 $target
echo ""

echo -e "${YELLOW}WebPulse Checks if this web server is vulnerable to directory traversal${RED} $target for port 80 ${NC}"
echo ""
nmap --script http-passwd --script-args http-passwd.root=/test/ -Pn -T4 -p80 $target
echo ""
echo -e "${YELLOW}WebPulse finished checking ${RED}HTTP${NC} ${YELLOW}information.${NC}"
# Port 80 HTTP code ends here

# Port 443 HTTPS code starts here
echo ""
echo -e "${YELLOW}WebPulse running some open CVE check${RED} $target for port 443 ${NC}"
echo ""
nmap -sV --script http-vuln-cve2014-2126,http-vuln-cve2014-2127,http-vuln-cve2014-2128,http-vuln-cve2014-2129 -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse enumerates themes & plugins of Wordpress installations${RED} $target for port 443 ${NC}"
echo ""
nmap -sV --script http-wordpress-brute -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse Enumerates usernames in Wordpress blog/CMS${RED} $target for port 443 ${NC}"
echo ""
nmap -sV --script http-wordpress-brute -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse checking http errors${RED} $target for port 443 ${NC}"
echo ""
nmap -sV --script http-errors.nse -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse checking http unsafe output escaping${RED} $target for port 443 ${NC}"
echo ""
nmap -sV --script=http-unsafe-output-escaping -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse detects Cross Site Request Forgeries (CSRF) vulnerabilities${RED} $target for port 443 ${NC}"
echo ""
nmap -sV --script http-csrf.nse -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse Tests for access with default credentials${RED} $target for port 443 ${NC}"
echo ""
nmap --script http-default-accounts -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse checking insecure file upload forms${RED} $target for port 443 ${NC}"
echo ""
nmap --script http-fileupload-exploiter.nse -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse enumerates the Drupal modules${RED} $target for port 443 ${NC}"
echo ""
nmap --script http-drupal-enum -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse enumerates Drupal users by exploiting an information disclosure${RED} $target for port 443 ${NC}"
echo ""
nmap --script=http-drupal-enum-users --script-args http-drupal-enum-users.root="/path/" -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse Checking http-exif-spider${RED} $target for port 443 ${NC}"
echo ""
nmap --script http-exif-spider -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse Checking if hosts are on Google's blacklist of suspected malware and phishing servers${RED} $target for port 443 ${NC}"
echo ""
nmap --script http-google-malware -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse Attempts to bypass password protected resources (HTTP 401 status)${RED} $target for port 443 ${NC}"
echo ""
nmap --script http-method-tamper -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse Uploads a local file to a remote web server using PUT Method${RED} $target for port 443 ${NC}"
echo ""
nmap --script http-put --script-args http-put.url='/uploads/rootme.php',http-put.file='/tmp/rootme.php' -Pn -T4 -p443 $target
echo ""

echo -e "${YELLOW}WebPulse Checking vulners and Service version${RED} $target for port 443 ${NC}"
echo ""
nmap -sV -sC --script vulners -Pn -T4 -p443 $target

echo ""
echo -e "${YELLOW}WebPulse Checking virtual hostnames related information${RED} $target for port 443 ${NC}"
echo ""
nmap --script http-vhosts -Pn -T4 -p443 $target

echo ""
echo -e "${YELLOW}WebPulse Checking HEAD request for the root folder${RED} $target for port 443 ${NC}"
echo ""
nmap -sV --script=http-headers -Pn -T4 -p443 $target

echo ""
echo -e "${YELLOW}WebPulse Checking potentially risky methods${RED} $target for port 443 ${NC}"
echo ""
nmap --script http-methods -Pn -T4 -p443 $target

echo ""
echo -e "${YELLOW}WebPulse Checking HTTP response headers related to security${RED} $target for port 443 ${NC}"
echo ""
nmap --script http-security-headers -Pn -T4 -p443 $target

echo ""
echo -e "${YELLOW}WebPulse attempts to exploit the "shellshock" vulnerability${RED} $target for port 443 ${NC}"
echo ""
nmap -sV --script http-shellshock -Pn -T4 -p443 $target

echo ""
echo -e "${YELLOW}WebPulse checking Slowloris DoS attack without actually launching a DoS attack${RED} $target for port 443 ${NC}"
echo ""
nmap --script http-slowloris-check -Pn -T4 -p443 $target

echo ""
echo -e "${YELLOW}WebPulse checking SQL injection attack${RED} $target for port 443 ${NC}"
echo ""
nmap -sV --script=http-sql-injection -Pn -T4 -p443 $target

echo ""
echo -e "${YELLOW}WebPulse running WhatWeb to check Web content info${RED} $target for port 443 ${NC}"
echo ""
whatweb $target

echo ""
echo -e "${YELLOW}WebPulse checking SSL info${RED} $target for port 443 ${NC}"
echo ""
openssl s_client -connect $target:443

echo ""
echo -e "${YELLOW}WebPulse checking SSL Ciphers${RED} $target for port 443 ${NC}"
echo ""
nmap -sV -Pn --script ssl-enum-ciphers -p443 $target

# Port 443 HTTPS code ends here
