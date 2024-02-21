package policy_cache_server

import (
	"github.com/miekg/dns"
)

func MakeDNSQuery(name string, queryType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), queryType)
	msg.SetEdns0(4096, true)
	msg.Id = dns.Id()
	return msg
}

func ConvertToByte(msg *dns.Msg) []byte {
	data, err := msg.Pack()
	if err != nil {
		return make([]byte, 0)
	}
	return data
}
