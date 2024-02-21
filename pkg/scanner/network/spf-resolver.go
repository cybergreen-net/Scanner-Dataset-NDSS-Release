package network

import (
	"Scanner/pkg/scanner/structs"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// LookupSPF returns spf txt record.
// if no records found or more than one record found, r value will be set accordingly to None or PermError.
// If dns lookup failed, r will be set to TempError.
func LookupSPF(domain string) (spf string, r structs.SPFError) {
	txts, err := lookupTXT(domain)
	if err != nil {
		return "", structs.TempError
	}

	var spfs []string
	for _, txt := range txts {
		txt = strings.ToLower(txt)
		if txt == "v=spf1" || strings.HasPrefix(txt, "v=spf1 ") {
			spfs = append(spfs, txt)
		}
	}

	switch len(spfs) {
	case 0:
		return "", structs.None
	case 1:
		return spfs[0], ""
	default:
		return "", structs.PermError
	}
}

// lookupTXT using miekg DNS since net.LookupTXT returns error if no TXT records
// returns slice of TXT records and error
func lookupTXT(d string) ([]string, error) {
	var txt []string

	r, _, err := dnsQuest(d, dns.TypeTXT)
	if err != nil {
		return txt, err
	}

	for _, answ := range r.Answer {
		if t, ok := answ.(*dns.TXT); ok {
			txt = append(txt, strings.Join(t.Txt, ""))
		}
	}
	return txt, nil
}

// returns IPs, MX count, error
func lookupMX(d string) ([]net.IP, int, error) {
	ips := make([]net.IP, 0)
	r, _, err := dnsQuest(d, dns.TypeMX)
	if err != nil {
		return ips, 0, err
	}

	for i, answ := range r.Answer {
		switch answ := answ.(type) {
		case *dns.MX:
			foundIPs, err := net.LookupIP(answ.Mx)
			if err != nil {
				return ips, i, err
			}
			ips = append(ips, foundIPs...)
		}
	}

	return ips, len(r.Answer), nil
}

func dnsQuest(d string, t uint16) (r *dns.Msg, rtt time.Duration, err error) {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.SetQuestion(dns.Fqdn(d), t)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)

	c := new(dns.Client)
	server := net.JoinHostPort(GoogleDNS, strconv.Itoa(DNSPort))
	return c.Exchange(m, server)
}
