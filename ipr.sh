#!/bin/bash

# Colors
RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; BLUE="\e[34m"; RESET="\e[0m"

REPORT_FILE="cloudbuster_report.txt"

banner() {
  echo -e "${BLUE}"
  echo "============================================"
  echo "           CLOUDBUSTER v1.0                 "
  echo "  Cloudflare Bypass & Real IP Recon Tool    "
  echo "============================================"
  echo -e "${RESET}"
}

check_dependencies() {
  echo -e "${BLUE}[+] Checking dependencies...${RESET}" | tee "$REPORT_FILE"
  for cmd in dig whois curl jq openssl host wafw00f httpx; do
    if ! command -v $cmd &> /dev/null; then
      echo -e "${RED}[!] $cmd is not installed. Please install it before running this script.${RESET}" | tee -a "$REPORT_FILE"
      exit 1
    fi
  done
}

get_target_info() {
  read -r -p "Enter target domain (e.g., example.com): " DOMAIN
  TARGET_IP=$(dig +short "$DOMAIN" | head -n1)

  echo -e "${YELLOW}[+] Target Domain:${RESET} $DOMAIN" | tee -a "$REPORT_FILE"
  echo -e "${YELLOW}[+] Resolved IP Address:${RESET} $TARGET_IP" | tee -a "$REPORT_FILE"
}

run_recon() {
  echo -e "\n${GREEN}[+] Enumerating Subdomains...${RESET}" | tee -a "$REPORT_FILE"
  curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sort -u | grep -v '\*' > found_subdomains.txt
  tee -a "$REPORT_FILE" < found_subdomains.txt

  echo -e "\n${GREEN}[+] Extracting SANs from SSL Cert...${RESET}" | tee -a "$REPORT_FILE"
  echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null |
    openssl x509 -noout -text | grep -A1 "Subject Alternative Name" | grep DNS: | tee -a "$REPORT_FILE"

  echo -e "\n${GREEN}[+] Checking TXT/SPF Records...${RESET}" | tee -a "$REPORT_FILE"
  dig TXT "$DOMAIN" +short | tee -a "$REPORT_FILE"

  echo -e "\n${GREEN}[+] Performing Reverse DNS Lookup...${RESET}" | tee -a "$REPORT_FILE"
  host "$TARGET_IP" | tee -a "$REPORT_FILE"

  echo -e "\n${GREEN}[+] WAF/CDN Detection using wafw00f...${RESET}" | tee -a "$REPORT_FILE"
  wafw00f "http://$DOMAIN" | tee -a "$REPORT_FILE"
}

waf_detection() {
  echo -e "\n${GREEN}[+] Detecting WAF using wafw00f...${RESET}" | tee -a "$REPORT_FILE"
  
  WAF_OUTPUT=$(wafw00f "http://$DOMAIN")

  if echo "$WAF_OUTPUT" | grep -iq "Cloudflare"; then
    echo -e "${GREEN}[+] WAF Detected: Cloudflare${RESET}" | tee -a "$REPORT_FILE"
  elif echo "$WAF_OUTPUT" | grep -iq "Akamai"; then
    echo -e "${GREEN}[+] WAF Detected: Akamai${RESET}" | tee -a "$REPORT_FILE"
  elif echo "$WAF_OUTPUT" | grep -iq "Sucuri"; then
    echo -e "${GREEN}[+] WAF Detected: Sucuri${RESET}" | tee -a "$REPORT_FILE"
  elif echo "$WAF_OUTPUT" | grep -iq "Incapsula"; then
    echo -e "${GREEN}[+] WAF Detected: Imperva Incapsula${RESET}" | tee -a "$REPORT_FILE"
  elif echo "$WAF_OUTPUT" | grep -iq "Fastly"; then
    echo -e "${GREEN}[+] WAF Detected: Fastly${RESET}" | tee -a "$REPORT_FILE"
  elif echo "$WAF_OUTPUT" | grep -iq "F5"; then
    echo -e "${GREEN}[+] WAF Detected: F5 BIG-IP${RESET}" | tee -a "$REPORT_FILE"
  else
    echo -e "${RED}[+] No specific WAF detected. Generic WAF detection indicated.${RESET}" | tee -a "$REPORT_FILE"
  fi
}

probe_real_ips() {
  echo -e "\n${GREEN}[+] Probing Subdomains for Real IPs...${RESET}" | tee -a "$REPORT_FILE"
  if command -v httpx &> /dev/null; then
    echo -e "[+] Running httpx..." | tee -a "$REPORT_FILE"
    httpx -l found_subdomains.txt -ip -silent > subdomain_ips.txt

    echo -e "[+] Extracting IPs and filtering possible real servers..." | tee -a "$REPORT_FILE"
    awk '{print $2}' subdomain_ips.txt | grep -v "$TARGET_IP" | sort -u > possible_bypasses.txt

    echo -e "[+] Checking for IPs that differ from $TARGET_IP (bypass candidates)..." | tee -a "$REPORT_FILE"
    if [[ -s possible_bypasses.txt ]]; then
      tee -a "$REPORT_FILE" < possible_bypasses.txt
    else
      echo -e "${RED}[-] No bypass candidates found.${RESET}" | tee -a "$REPORT_FILE"
    fi
  else
    echo -e "${RED}[!] httpx not installed. Skipping subdomain probing.${RESET}" | tee -a "$REPORT_FILE"
  fi
}

# Main
banner
check_dependencies
get_target_info
run_recon
waf_detection  # Add this function to invoke WAF detection
probe_real_ips

echo -e "\n${GREEN}[+] Recon Complete. Check ${REPORT_FILE} for details.${RESET}"


