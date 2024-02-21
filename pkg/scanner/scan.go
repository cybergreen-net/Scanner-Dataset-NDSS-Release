package scanner

import (
	"Scanner/pkg/config"
	"Scanner/pkg/scanner/network"
	"Scanner/pkg/scanner/structs"
	"crypto/x509"
	"net"
	"strconv"
)

func PerformTLSScan(request structs.Request) (structs.TLSCombinedRecord, error) {
	hostname := request.Hostname
	ipAddressesResolved, err := network.ResolveIPAddresses(hostname)
	response := structs.TLSCombinedRecord{}

	if err != nil {
		return response, err
	}

	var allowedIPAddresses []net.IP
	var filteredIPAddresses []net.IP
	if request.NoServer {
		allowedIPAddresses, filteredIPAddresses = ipAddressesResolved, make([]net.IP, 0)
	} else {
		allowedIPAddresses, filteredIPAddresses = network.IPBatchOptedOut(ipAddressesResolved)
	}
	if err != nil {
		return response, err
	}

	tlsTask := network.TLSRequest{
		ScannableIPAddresses: allowedIPAddresses,
		FilteredIPAddresses:  filteredIPAddresses,
		ResolvedIPAddresses:  ipAddressesResolved,
		Hostname:             hostname,
		Port:                 config.DefaultTLSPort,
		Type:                 "TLS",
	}

	records, _ := tlsTask.ParallelIPScan()

	return records, nil
}

func PerformMailScan(mailHostsToIPs map[string][]net.IP,
	resolvedHostToIPs map[string][]net.IP,
	filteredHostsToIPs map[string][]net.IP,
	cachedMXs map[string]struct{},
	MXSpecificDataOut chan<- map[string]structs.MXSpecificData) {

	smtpTasks := make([]network.TLSRequest, 0)
	bannerMetadataTask := make([]string, 0)
	for host, ipList := range mailHostsToIPs {
		// Don't rescan cached MXs
		if _, ok := cachedMXs[host]; ok {
			continue
		}
		openPorts := network.PerformGreedyPortScan(ipList)
		for _, port := range openPorts {
			smtpTLSTask := network.TLSRequest{
				ScannableIPAddresses: ipList,
				FilteredIPAddresses:  filteredHostsToIPs[host],
				ResolvedIPAddresses:  resolvedHostToIPs[host],
				Hostname:             host,
				Port:                 strconv.Itoa(port),
				Type:                 "SMTP",
			}
			smtpTasks = append(smtpTasks, smtpTLSTask)
			bannerMetadataTask = append(bannerMetadataTask, net.JoinHostPort(host, strconv.Itoa(port)))
		}
	}

	smtpMetadata := network.ParallelMailMetadataScan(bannerMetadataTask)

	allMXSpecificData := network.ParallelHostnameScan(smtpTasks)
	for hostPort, bannerInfo := range smtpMetadata {
		host, _, _ := net.SplitHostPort(hostPort)
		allMXSpecificData[host].MXMetaData[hostPort] = bannerInfo
	}
	MXSpecificDataOut <- allMXSpecificData
}

func PerformMTASTSScan(request structs.Request, mxServers []string, out chan<- structs.MTASTSRecord) {
	hostname := request.Hostname
	query := network.MTASTS{Hostname: hostname, MXRecordsForHostname: mxServers}
	out <- query.Query()

}

func PerformDMARCLookup(request structs.Request, out chan<- structs.DMARCRecord) {
	hostname := request.Hostname
	query := network.DMARC{Hostname: hostname}
	out <- query.LookupDMARCRecords()
}

func LookupSPF(request structs.Request, out chan<- structs.CombinedSPFRecord) {
	hostname := request.Hostname
	query := network.SPF{Hostname: hostname}
	out <- query.Query()
}

func LookupTLSARecords(mailServers []string, out chan<- map[string]structs.TLSAContainer) {
	mailHostsToIPs := network.ResolveIPAddressesForHostnames(mailServers)

	query := network.TLSA{MailHostsToIPs: mailHostsToIPs}
	out <- query.QueryRecords()
}

func PerformTLSAScan(mailServers []string,
	ipPortToCertificates map[string][]*x509.Certificate,
	hostPortTLSARecords map[string]structs.TLSAContainer) map[string]interface{} {
	mailHostsToIPs := network.ResolveIPAddressesForHostnames(mailServers)
	query := network.TLSA{
		MailHostsToIPs:        mailHostsToIPs,
		IPPortToCertificates:  ipPortToCertificates,
		HostPortToTLSARecords: hostPortTLSARecords,
	}
	return query.VerifyIPs()
}

func PerformDNSSECScan(request structs.DNSRequest) structs.DNSSECRecord {
	query := network.DNSSEC{Hostname: request.Hostname, QueryType: request.QueryType, NoServer: request.NoServer}
	return query.Query()
}
