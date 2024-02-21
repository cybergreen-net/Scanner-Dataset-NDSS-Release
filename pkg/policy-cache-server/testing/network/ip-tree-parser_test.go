package network

import (
	server "Scanner/pkg/policy-cache-server"
	"testing"
)

func TestValidateIPParsing(t *testing.T) {
	ipDataReadList := []string{
		"1.1.1.1/24", // Valid IPv4 CIDR
		"192.0.0.1",  // Valid IPv4 Address

		"299.299.299.299", // Invalid IPv4 Address
		"254.254.299.0/8", // Invalid IPv4 CIDR Address

		"2001:0db8:85a3:0000:0000:8a2e:0370:7334", // Valid IPv6 Address
		"fghi:abcd:0123::",                        // Invalid IPv6 Address

		"2001:db8:1234::/48", // Valid IPv6 CIDR
		"fgg::/64",           // Invalid IPv6 CIDR

		"# this is a test comment", // Configuration comment line
		"                ",         // Misconfigured space
		" ",                        // Spaces
		"",                         // Empty String
	}

	_, erroredEntries := server.ProcessTreeFromList(ipDataReadList)

	expectedErroredEntries := []string{
		"299.299.299.299",          // Invalid IPv4 Address
		"254.254.299.0/8",          // Invalid IPv4 CIDR Address
		"fghi:abcd:0123::",         // Invalid IPv6 Address
		"fgg::/64",                 // Invalid IPv6 CIDR
		"# this is a test comment", // Configuration comment line
		"                ",         // Misconfigured space
		" ",                        // Spaces
		"",                         // Empty String
	}
	if len(erroredEntries) != len(expectedErroredEntries) {
		t.Fail()
	}
}
