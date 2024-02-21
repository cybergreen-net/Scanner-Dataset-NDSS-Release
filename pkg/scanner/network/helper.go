package network

import (
	"github.com/miekg/dns"
	"net"
)

func convertDnsNStoNetNS(in []dns.NS) []*net.NS {
	results := make([]*net.NS, 0)
	for _, rr := range in {
		ns := &net.NS{Host: rr.Ns}
		results = append(results, ns)
	}
	return results
}
