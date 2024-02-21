package network

import (
	"net"

	"github.com/miekg/dns"
)

const MaxReturnedIPAddressesCount = 64

func (resolver *Resolver) StrictNSQuery(qname string, qtype uint16, noserver bool) (rrSet []dns.RR, chain *AuthenticationChain, err error) {
	if len(qname) < 1 {
		return nil, nil, ErrInvalidQuery
	}

	answer, err := queryRRset(qname, qtype, noserver)
	if err != nil {
		return nil, nil, err
	}

	if answer.IsEmpty() {
		return nil, nil, ErrNoResult
	}

	if !answer.IsSigned() {
		return nil, nil, ErrResourceNotSigned
	}

	signerName := answer.SignerName()

	authChain := NewAuthenticationChain()
	err = authChain.Populate(signerName, noserver)

	if err == ErrNoResult {
		return nil, nil, err
	}

	err = authChain.Verify(answer)
	if err != nil {
		return nil, authChain, err
	}

	return answer.RrSet, authChain, nil
}

func FormatResultRRs(signedRrset *RRSet) []net.IP {
	ips := make([]net.IP, 0, len(signedRrset.RrSet))
	for _, rr := range signedRrset.RrSet {
		switch t := rr.(type) {
		case *dns.A:
			ips = append(ips, t.A)
		case *dns.AAAA:
			ips = append(ips, t.AAAA)
		}
	}
	return ips
}
