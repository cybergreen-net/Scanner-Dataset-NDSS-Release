package network

const (
	// MTA_STS
	MTA_STS_DNS_PREFIX            = "_mta-sts"
	MTA_STS_HTTPS_PREFIX          = "mta-sts"
	MTA_STS_HTTPS_POLICY_LOCATION = ".well-known/mta-sts.txt"
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

// Unable to create array constants
var (
	// SPFLookupTags includes SPF lookups that count towards the 10 lookup limit
	// https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
	SPFLookupTags = [6]string{"include", "a", "mx", "ptr", "exists", "redirect"}
)
