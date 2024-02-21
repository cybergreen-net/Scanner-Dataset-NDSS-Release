#!/bin/bash
set +eax

# shellcheck disable=SC2034
cecho(){
    RED="\033[0;31m"
    GREEN="\033[0;32m"
    YELLOW="\033[0;33m"
    CYAN="\033[1;36m"
    NC="\033[0m" # No Color
    # shellcheck disable=SC2059
    printf "${!1}${2} ${NC}\n" # <-- bash
}

if ! [ -x "$(command -v jq)" ]; then
  echo 'Error: jq is not installed. Please install jq to proceed'
  exit 1
fi

cecho "CYAN" "Running Tests"

cecho "YELLOW" "TLS Scan - Valid TLS Certificate"
result=$(bin/scan tls --hostname cloudflare.com. | jq -r '.certificate | to_entries | .[].value.status.isValid')
readarray -t certValidityArray <<< "$result"
for data in "${certValidityArray[@]}"
do
  if [[ "$data" != "true" ]]; then
    cecho "RED" "[FAIL] Requested Certificate is Invalid"
  else
    cecho "GREEN" "[PASS] Requested Certificate is Valid"
  fi
done

cecho "YELLOW" "TLS Scan - Invalid TLS Certificate"
result=$(bin/scan tls --hostname expired.badssl.com. | jq -r '.certificate | to_entries | .[].value.status.isValid')
certValidityArray=("$result")
for data in "${certValidityArray[@]}"
do
  if [[ "$data" != "false" ]]; then
    cecho "RED" "[FAIL] Requested Certificate is Valid. Expected to be Invalid"
  else
    cecho "GREEN" "[PASS] Requested Certificate is Invalid as expected"
  fi
done

cecho "YELLOW" "TLS Scan - Checking Website with Cert containing no CN Info"
result=$(bin/scan tls --hostname no-common-name.badssl.com. | jq -r '.certificate | to_entries | .[].cn')

if [[ "$result" != "null" ]]; then
  cecho "RED" "[FAIL] Requested Certificate has a CN field. Expected no CN information."
else
  cecho "GREEN" "[PASS] Requested Certificate has no CN field as expected"
fi

cecho "CYAN" "Completed Running Tests"
