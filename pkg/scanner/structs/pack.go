package structs

import (
	"crypto/x509"
	"encoding/hex"
	"net"
)

type SerializedIPAddresses struct {
	IPs       []string
	IPv4Count int
	IPv6Count int
}

func SerializeIPAddresses(ips []net.IP) SerializedIPAddresses {
	response := SerializedIPAddresses{}
	ipAddressStrings := make([]string, 0)
	ipv4Count := 0
	ipv6Count := 0
	for _, ip := range ips {
		ipAddressStrings = append(ipAddressStrings, ip.String())
		if ip.To4() != nil {
			ipv4Count += 1
		} else {
			ipv6Count += 1
		}
	}
	response.IPs = ipAddressStrings
	response.IPv4Count = ipv4Count
	response.IPv6Count = ipv6Count
	return response
}

// SerializePublicKey Returns "Undecipherable Key" on error
func SerializePublicKey(pk any) string {
	str, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return "Undecipherable Key"
	}
	return hex.EncodeToString(str)
}
