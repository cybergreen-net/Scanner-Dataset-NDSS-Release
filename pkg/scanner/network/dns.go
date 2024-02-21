package network

import (
	"Scanner/pkg/config"
	structs2 "Scanner/pkg/scanner/structs"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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

func ResolveMTASTSDNSRecord(hostname string) (structs2.MTATextRecord, bool) {
	result := structs2.MTATextRecord{}

	mtaQueryString := fmt.Sprintf("%s.%s", MTA_STS_DNS_PREFIX, hostname)
	mtaQueryASCII, err := idna.ToASCII(mtaQueryString)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, true
	}
	mtaQueryASCII = dns.Fqdn(mtaQueryASCII)

	mtaRecord, err := exchange(mtaQueryASCII, dns.TypeTXT)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, true
	}

	for _, ansRR := range mtaRecord.Answer {
		if t, ok := ansRR.(*dns.TXT); ok {
			version := ""
			id := ""
			extensions := make([]structs2.Pair, 0)
			// convert "v=STSv1; id=20190429T010101;"" to "v=STSv1 id=20190429T010101"
			txtStr := strings.ReplaceAll(t.Txt[0], ";", "")
			// convert to [v=STSv1, id=20190429T010101]
			attributes := strings.Split(txtStr, " ")
			for index, token := range attributes {
				keyValue := strings.Split(token, "=")
				if len(keyValue) != 2 {
					result.Errors = append(result.Errors, "invalid key value syntax")
					break
				}
				// first key value pair MUST be version
				if index == 0 && keyValue[0] != "v" {
					result.Errors = append(result.Errors, "first attribute is not version!")
					break
				}

				switch keyValue[0] {
				case "v":
					version = keyValue[1]
				case "id":
					id = keyValue[1]
				default:
					extensions = append(extensions, structs2.Pair{Key: keyValue[0], Value: keyValue[1]})
				}
			}
			// possible invalid sequences
			if version == "" {
				result.Errors = append(result.Errors, "missing required version")
				continue
			} else if id == "" {
				result.Errors = append(result.Errors, "missing required id")
				continue
			} else if version != "" && id != "" && result.Version != "" {
				// if more than one valid MTA-STS record exists, then error
				result.Errors = append(result.Errors, "more than one valid MTA-STS TXT record, not allowed!")
				result.Valid = false
				continue
			}
			// valid, woo! store the version, id, and extensions fields
			result.Version = version
			result.ID = id
			result.Extensions = extensions

		}
		if _, ok := ansRR.(*dns.CNAME); ok {
			result.HasCNAME = true
			// Simply follow through because the resolver will return the followed CNAME TXT records
		}
	}
	// mta not valid if no record is found
	if result.Version == "" || result.ID == "" {
		result.Valid = false
		return result, false
	}

	return result, true
}

func ResolveCAARecord(hostname string) structs2.CAARecord {
	result := structs2.CAARecord{}
	issuerTagMap := make(map[structs2.Issuer]structs2.CAAResourceRecord)
	issuerWildTagMap := make(map[structs2.Issuer]structs2.CAAResourceRecord)
	iodefTagList := make([]string, 0)

	asciiHostname, err := idna.ToASCII(hostname)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}

	caaRR, err := exchange(dns.Fqdn(asciiHostname), dns.TypeCAA)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}

	for _, rr := range caaRR.Answer {
		switch t := rr.(type) {
		case *dns.CAA:
			flag := t.Flag
			tag := t.Tag
			value := t.Value

			switch strings.ToLower(tag) {
			case "issue":
				issuer, kvRecords := structs2.ParseCAAValue(flag, value)
				issuerTagMap[issuer] = kvRecords
			case "issuewild":
				issuer, kvRecords := structs2.ParseCAAValue(flag, value)
				issuerWildTagMap[issuer] = kvRecords
			case "iodef":
				iodefTagList = append(iodefTagList, value)
			default:
				continue
			}
		}
	}

	result.IssueTag = issuerTagMap
	result.IssueWildTag = issuerWildTagMap
	result.IODefTag = iodefTagList

	return result
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
