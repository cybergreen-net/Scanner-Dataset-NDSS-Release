package network

import (
	policy_cache_server "Scanner/pkg/policy-cache-server"
	"github.com/zmap/go-iptree/iptree"
	"testing"
)

func TestValidateIPBlocking(t *testing.T) {
	optOutIPs := []string{
		"103.17.20.0",   // edge case for 103.17.20.0/24
		"103.17.20.255", // edge case for 103.17.20.0/24
		"103.17.20.128", // general case for 103.17.20.0/24
		"2401:2880:0000:0000:0000:0000:0000:0000", // edge case for 2401:2880::/32
		"2401:2880:ffff:ffff:ffff:ffff:ffff:ffff", // edge case for 2401:2880::/32
		"2401:2880:0000:0000:0000:ffff:abcd:0000", // general case for 2401:2880::/32
	}

	validIPs := []string{
		"103.17.19.255",                           // edge case for 103.17.20.0/24
		"103.17.21.0",                             // edge case for 103.17.20.0/24
		"2401:2879:ffff:ffff:ffff:ffff",           // edge case for 2401:2880::/32
		"2401:2881:0000:0000:0000:0000:0000:0000", // edge case for 2401:2880::/32
	}

	blockedIPs := []string{
		"202.91.160.0/20",
		"2401:2880::/32",
		"103.17.20.0/24",
		"142.250.217.69",
	}

	tree := iptree.New()
	for _, blockedIP := range blockedIPs {
		tree.AddByString(blockedIP, 0)
	}

	policyKV := policy_cache_server.IPPrefixTree{Tree: tree}

	for _, ip := range optOutIPs {
		_, exists, _ := policyKV.Tree.GetByString(ip)
		// All tested IPs should match a block list criteria
		if !exists {
			t.Fail()
		}
	}

	for _, ip := range validIPs {
		_, exists, _ := policyKV.Tree.GetByString(ip)
		// All tested IPs should not match a block list criteria
		if exists {
			t.Fail()
		}
	}
}
