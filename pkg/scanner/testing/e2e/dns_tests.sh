set +eax

# DNS Scan contains DNSSEC, and isValid, and no lame delegations. listed nameservers
bin/scan dns --hostname cloudflare.com. --json --pretty
# DNS Scan contains no DNSSEC (hence isValid is false), no lame delegations, listed nameservers
bin/scan dns --hostname google.com. --json --pretty
# DNS Scan contains lame delegations and no DNSSEC, listed nameservers
bin/scan dns --hostname meity.gov.in. --json --pretty
# DNS Scan for an invalid hostname, returns no name servers
bin/scan dns --hostname this.does.not.exist.com --json --pretty
