package network

import (
	"Scanner/pkg/scanner/structs"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/shuque/dane"
)

type TLSA struct {
	MailHostsToIPs        map[string][]net.IP              // host : ip
	IPPortToCertificates  map[string][]*x509.Certificate   // ip+port : certificate chain
	HostPortToTLSARecords map[string]structs.TLSAContainer // host+port : tlsa record
}

var (
	ErrTLSANonexistant = errors.New("E_TLSA_NOEXIST")
)

// Given a map of mail server hostnames and IPs, ip+ports mapped to certificates, and host+port tlsa records,
// resolve TLSA status for each ip
func verifyIPsWithTLSARecords(hostsIPs map[string][]net.IP,
	ipPortToCertificates map[string][]*x509.Certificate,
	hostPortTLSARecords map[string]structs.TLSAContainer) map[string]interface{} {

	mxPortTLSARecord := make(map[string]interface{})
	for hostname, IPs := range hostsIPs {
		for _, port := range SMTPPorts {
			qname := fmt.Sprintf("_%d._tcp.%s", port, hostname)
			tlsaRecord := structs.TLSARecord{ValidIPs: make([]string, 0), InvalidIPs: make(map[string]string)}
			// retrieve TLSA record
			tlsaContainer, ok := hostPortTLSARecords[net.JoinHostPort(hostname, strconv.Itoa(port))]
			if !ok || (tlsaContainer.Error != "") {
				tlsaRecord.TLSARecordExists = false
				mxPortTLSARecord[qname] = ErrTLSANonexistant.Error()
				continue
			}
			tlsaRecord.TLSARecordExists = true
			// retrieve certificates
			for _, ip := range IPs {
				certChain, ok := ipPortToCertificates[net.JoinHostPort(ip.String(), strconv.Itoa(port))]
				if !ok {
					tlsaRecord.InvalidIPs[ip.String()] = "error retrieving certificates"
					continue
				}
				// verify
				daneconfig := dane.NewConfig(hostname, ip, port)
				daneconfig.TLSA = tlsaContainer.TLSARecord
				daneconfig.DANEChains = append(daneconfig.DANEChains, certChain)
				recordValidity := false
				for _, tlsardata := range tlsaContainer.TLSARecord.Rdata {
					resdaneok := dane.AuthenticateSingle(certChain, tlsardata, daneconfig)
					if !recordValidity && resdaneok {
						recordValidity = resdaneok
					}
					fmt.Printf("resdaneok: %v\n", resdaneok)
				}
				tlsaRData := daneconfig.TLSA.Rdata[0]
				tlsaRecord.MatchType = int(tlsaRData.Mtype)
				tlsaRecord.Selector = int(tlsaRData.Selector)
				tlsaRecord.Usage = int(tlsaRData.Usage)
				if recordValidity {
					tlsaRecord.ValidIPs = append(tlsaRecord.ValidIPs, ip.String())
				} else {
					tlsaRecord.InvalidIPs[ip.String()] = "failed to find matching TLSA record"
				}
			}
			mxPortTLSARecord[qname] = tlsaRecord
		}

	}
	return mxPortTLSARecord
}

// Retrieves and returns TLSA records, stored in dane.config objects
func retrieveTLSARecords(MailHostsToIPs map[string][]net.IP) map[string]structs.TLSAContainer {
	servers := []*dane.Server{dane.NewServer("", CloudflareDNS, 53)}
	resolver := dane.NewResolver(servers)

	ipToTLSARecords := make(map[string]structs.TLSAContainer)
	for hostname := range MailHostsToIPs {
		for _, port := range SMTPPorts {
			tlsaRecord := structs.TLSAContainer{}
			tlsa, err := dane.GetTLSA(resolver, hostname, port)
			if err != nil {
				tlsaRecord.Error = err.Error()
			} else if tlsa == nil {
				tlsaRecord.Error = "no tlsa records found"
			} else {
				tlsaRecord.TLSARecord = tlsa
			}
			ipToTLSARecords[net.JoinHostPort(hostname, strconv.Itoa(port))] = tlsaRecord
		}
	}
	return ipToTLSARecords

}

func (t TLSA) VerifyIPs() map[string]interface{} {
	// not parallelized if hostporttotlsarecords is not filled out prior to calling this method
	if t.HostPortToTLSARecords == nil {
		t.HostPortToTLSARecords = t.QueryRecords()
	}
	return verifyIPsWithTLSARecords(t.MailHostsToIPs, t.IPPortToCertificates, t.HostPortToTLSARecords)
}

func (t TLSA) QueryRecords() map[string]structs.TLSAContainer {
	return retrieveTLSARecords(t.MailHostsToIPs)
}
