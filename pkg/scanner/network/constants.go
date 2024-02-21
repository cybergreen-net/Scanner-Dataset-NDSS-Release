package network

const (
	// SERVER
	IP_QUERY  = "http://%s/restricted-ip?ip=%s"
	MSG_QUERY = "http://%s/get-msg?tld=%s&type=%d"
	MX_QUERY  = "http://%s/get-mx/%s"
	MX_PUT    = "http://%s/put-mx/%s"

	// list of DNS servers used in DNSSEC
	CloudflareDNS = "1.1.1.1"
	GoogleDNS     = "8.8.8.8"
	NextDNS       = "9.9.9.9"
	DNSPort       = 53
)
