package structs

import "github.com/miekg/dns"

type CombinedDNSRecord struct {
	Hostname     string       `json:"hostname"`
	Resolved     bool         `json:"queryTypeResolved"`
	DNSSECRecord DNSSECRecord `json:"dnssecRecord"`
	NSRecords    []string     `json:"nsRecords"`
}

type DNSSECRecord struct {
	DNSSECExists bool         `json:"dnssecExists"`
	DNSSECValid  bool         `json:"dnssecValid"`
	Reason       string       `json:"reason"`
	SignedZones  []SignedZone `json:"signedZones"`
}

type RRSet struct {
	RrSet []dns.RR   `json:"RrSet"`
	RrSig *dns.RRSIG `json:"RrSig"`
}

type SignedZone struct {
	Zone   string `json:"zone"`
	Dnskey *RRSet `json:"dnskey"`
	Ds     *RRSet `json:"ds"`
	// ParentZone   *SignedZone            `json:"parentZone"`
	PubKeyLookup map[uint16]*dns.DNSKEY `json:"pkLookup"`
}
