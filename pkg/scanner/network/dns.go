package network

import (
	"Scanner/pkg/config"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// Errors returned by the verification/validation methods at all levels.
var (
	ErrHTTPStatus  = errors.New("http status code is not 200")
	ErrHTTPConnect = errors.New("unable to connect to http server")
	ErrIPOptedOut  = errors.New("ip on opt out list")
)

func exchange(hostname string, queryType uint16) (*dns.Msg, error) {
	query := new(dns.Msg)
	query.SetQuestion(hostname, queryType)

	reply, err := dns.Exchange(query, config.DefaultResolver)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func ResolveIPAddresses(domainName string) ([]net.IP, error) {
	asciiDomainName, err := idna.ToASCII(domainName)
	if err != nil {
		return nil, err
	}
	var r net.Resolver
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*config.IP_SECOND_TIMEOUT)
	defer cancel()
	IPs, err := r.LookupIP(ctx, "ip", dns.Fqdn(asciiDomainName))
	if err != nil {
		return nil, err
	}
	return IPs, nil
}

func ResolveMXRecords(mailHost string) ([]string, map[string]uint16, error) {
	asciiMailHostName, err := idna.ToASCII(mailHost)
	if err != nil {
		return nil, nil, err
	}
	mailServerList, err := net.LookupMX(asciiMailHostName)
	if err != nil {
		return nil, nil, err
	}
	mailServers := make([]string, 0)
	mailServerPriority := make(map[string]uint16)
	for _, mx := range mailServerList {
		mailServers = append(mailServers, mx.Host)
		mailServerPriority[mx.Host] = mx.Pref
	}
	return mailServers, mailServerPriority, err
}

func ResolveIPAddressesForHostnames(hostnames []string) map[string][]net.IP {
	response := make(map[string][]net.IP, 0)
	for _, hostname := range hostnames {
		ipAddresses, err := ResolveIPAddresses(hostname)
		if err != nil {
			emptyIPList := make([]net.IP, 0)
			response[hostname] = emptyIPList
			continue
		}
		response[hostname] = ipAddresses
	}
	return response
}

func ConvertQueryTypeStringToDNSType(qType string) uint16 {
	for dnsType, dnsTypeAsString := range dns.TypeToString {
		if dnsTypeAsString == qType {
			return dnsType
		}
	}
	return dns.TypeA // If query lookup results in a fail, return the dns.TypeA record as default.
}

func IPBatchOptedOut(ips []net.IP) ([]net.IP, []net.IP) {
	allowedIPs := make([]net.IP, 0)
	ignoredIPs := make([]net.IP, 0)

	for _, ip := range ips {
		err := IPOptedOut(ip)
		if err != nil {
			ignoredIPs = append(ignoredIPs, ip)
			continue
		}
		allowedIPs = append(allowedIPs, ip)
	}
	return allowedIPs, ignoredIPs
}

func IPOptedOut(ip net.IP) error {
	resp, err := http.Get(fmt.Sprintf(IP_QUERY, config.GetServerHostnamePort(), ip.String()))
	if err != nil {
		return errors.New("Unable to access ip opt out list server: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrHTTPStatus
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	body := string(bytes)
	if body == "true" {
		return ErrIPOptedOut
	}
	return nil
}
