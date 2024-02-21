package scanner

import (
	"Scanner/pkg/scanner/network"
	"Scanner/pkg/scanner/storage"
	"Scanner/pkg/scanner/structs"
	"net"

	"github.com/miekg/dns"
	"github.com/urfave/cli/v2"
)

func HandleTLSScanRequests(context *cli.Context) error {
	hostname := context.String("hostname")
	noserver := context.Bool("noserver")

	records, err := PerformTLSScan(structs.Request{Hostname: hostname, NoServer: noserver})
	if err != nil {
		mapError := make(map[string]string, 0)
		mapError["error"] = err.Error()
		return storage.GenerateOutputAndTeardown(context, structs.TLSCombinedRecord{Errors: mapError, Hostname: hostname})
	}

	return storage.GenerateOutputAndTeardown(context, records)
}

func HandleMailScanRequests(context *cli.Context) error {
	hostname := context.String("hostname")
	noserver := context.Bool("noserver")
	nocachemx := context.Bool("no-cache-mx")

	mailServers, mailServerPriority, err := network.ResolveMXRecords(hostname)
	mailScanResponse := structs.MailScanCombinedRecord{}
	if err != nil {
		mailScanResponse.MailHost = hostname
	}

	scannedRecords := make(chan map[string]structs.MXSpecificData, 1)
	// Populuated by cache and eventually scanned MX records
	allRecordsAndCertificates := make(map[string]structs.MXSpecificData)

	// Check for MX IP opt out
	mailHostsToIPs := network.ResolveIPAddressesForHostnames(mailServers)
	scannableMailHostsToIPs := make(map[string][]net.IP)
	filteredMailHostsToIPs := make(map[string][]net.IP)
	var scannableIPs []net.IP
	var filteredIPs []net.IP
	for mxHost, ips := range mailHostsToIPs {
		if noserver {
			scannableIPs, filteredIPs = ips, make([]net.IP, 0)
		} else {
			scannableIPs, filteredIPs = network.IPBatchOptedOut(ips)
		}
		scannableMailHostsToIPs[mxHost] = scannableIPs
		filteredMailHostsToIPs[mxHost] = filteredIPs
	}

	// Retrieve all cached MX TLS and Certs
	cachedMXs := make(map[string]struct{})
	if !noserver {
		for _, mxHost := range mailServers {
			cacheResult, err := network.GetMXData(mxHost)
			if err == nil {
				cachedMXs[mxHost] = struct{}{}
				allRecordsAndCertificates[mxHost] = cacheResult
				delete(mailHostsToIPs, mxHost)
			}
		}
	}

	go PerformMailScan(scannableMailHostsToIPs,
		mailHostsToIPs,
		filteredMailHostsToIPs,
		cachedMXs,
		scannedRecords)

	// Cache MX data & join scanned data with cached mx data
	for hostname, data := range <-scannedRecords {
		if !(noserver || nocachemx) {
			// populate PortCount, TLSVersionCount, TLSCipherSuiteCount
			network.SetMXData(data, hostname)
		}
		allRecordsAndCertificates[hostname] = data
	}

	// Dump all data
	mailRecords := make(map[string]structs.TLSCombinedRecord)
	bannerAndCapabilties := make(map[string]structs.SMTPMetadata)
	for _, v := range allRecordsAndCertificates {
		for ipPort, tlsData := range v.MXTLSInformation {
			mailRecords[ipPort] = tlsData
		}
		for ipPort, mxMetadata := range v.MXMetaData {
			bannerAndCapabilties[ipPort] = mxMetadata
		}
	}

	mailScanResponse.MailHost = hostname
	mailScanResponse.ResolvedMX = mailServers
	mailScanResponse.MXServerPriority = mailServerPriority
	mailScanResponse.NumResolvedMX = len(mailServers)
	mailScanResponse.MXTLSInformation = mailRecords
	mailScanResponse.MailServerMetadata = bannerAndCapabilties
	mailScanResponse.IdentifyReachableAndSecurePorts()

	return storage.GenerateOutputAndTeardown(context, mailScanResponse)
}

func HandleDNSScanRequests(context *cli.Context) error {
	hostname := dns.Fqdn(context.String("hostname"))
	noserver := context.Bool("noserver")

	queryType := network.ConvertQueryTypeStringToDNSType(context.String("query-type"))
	request := structs.DNSRequest{Hostname: hostname, QueryType: queryType, NoServer: noserver}

	dnssec := PerformDNSSECScan(request)
	resolved := false

	if dnssec.Reason != network.ErrNoResult.Error() {
		resolved = true
	}
	ns, err := net.LookupNS(hostname)
	nameServers := make([]string, 0)
	if err == nil {
		for _, n := range ns {
			nameServers = append(nameServers, n.Host)
		}
	}
	return storage.GenerateOutputAndTeardown(context, structs.CombinedDNSRecord{
		Hostname:     hostname,
		DNSSECRecord: dnssec,
		NSRecords:    nameServers,
		Resolved:     resolved,
	})
}
