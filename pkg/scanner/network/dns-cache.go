package network

import (
	"Scanner/pkg/config"
	"Scanner/pkg/scanner/structs"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/miekg/dns"
)

func SetMXData(cacheData structs.MXSpecificData, hostname string) bool {
	ports := make(map[string]struct{})
	versions := make(map[uint16]struct{})
	cipherSuites := make(map[string]struct{})

	// Retrieve port count, TLS version count, and cipher suite count
	for hostPort, _ := range cacheData.MXTLSInformation {
		_, port, _ := net.SplitHostPort(hostPort)
		ports[port] = void{}
		for _, cipherSuiteData := range cacheData.MXTLSInformation[hostPort].CipherSuites {
			for _, versionSuiteData := range cipherSuiteData {
				if versionSuiteData.IsSupported {
					versions[versionSuiteData.TLSVersion] = void{}
					for cs, _ := range versionSuiteData.SupportedCipherSuites {
						cipherSuites[fmt.Sprintf("%d-%d", versionSuiteData.TLSVersion, cs)] = void{}
					}
				}
			}
		}
	}

	cacheData.PortCount = len(ports)
	cacheData.TLSVersionCount = len(versions)
	cacheData.TLSCipherSuiteCount = len(cipherSuites)

	path := fmt.Sprintf(MX_PUT, config.GetServerHostnamePort(), hostname)
	b, err := json.Marshal(cacheData)
	if err != nil {
		return false
	}
	body := []byte(b)

	r, err := http.NewRequest("POST", path, bytes.NewBuffer(body))
	if err != nil {
		return false
	}

	client := &http.Client{}
	res, err := client.Do(r)
	if err != nil {
		return false
	}

	defer res.Body.Close()

	res.Body.Close()
	return true
}

func GetMXData(hostname string) (structs.MXSpecificData, error) {
	path := fmt.Sprintf(MX_QUERY, config.GetServerHostnamePort(), hostname)
	resp, err := http.Get(path)
	if err != nil {
		return structs.MXSpecificData{}, errors.New("unable to access mx cache server: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return structs.MXSpecificData{}, ErrHTTPStatus
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return structs.MXSpecificData{}, err
	}

	if len(bytes) == 0 {
		return structs.MXSpecificData{}, errors.New("cache miss")
	}

	var cachedMX structs.MXSpecificData
	_ = json.Unmarshal(bytes, &cachedMX)
	return cachedMX, nil
}

func retrieveCachedNS(hostname string, noserver bool) ([]*net.NS, error) {
	msg, err := cachedExchange(hostname, dns.TypeNS, noserver)
	if err != nil {
		return nil, err
	}
	return dnsNSFromMsg(msg), nil
}

func dnsNSFromMsg(msg *dns.Msg) []*net.NS {
	nsRecords := make([]dns.NS, 0)
	for _, answer := range msg.Answer {
		if nsRecord, ok := answer.(*dns.NS); ok {
			nsRecords = append(nsRecords, *nsRecord)
		}
	}
	return convertDnsNStoNetNS(nsRecords)
}

// returns error on cache miss
func cachedExchange(hostname string, queryType uint16, noserver bool) (*dns.Msg, error) {
	if noserver {
		return nil, errors.New("noserver boolean set")
	}
	resp, err := http.Get(fmt.Sprintf(MSG_QUERY, config.GetServerHostnamePort(), hostname, queryType))
	if err != nil {
		return nil, errors.New("unable to access ip opt out list server: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrHTTPStatus
	}

	bytes, err := io.ReadAll(resp.Body)
	if len(bytes) == 0 || err != nil {
		return nil, errors.New("cache miss")
	}
	return NetBytestoNetMsg(bytes), nil
}

func NetBytestoNetMsg(data []byte) *dns.Msg {
	msg := dns.Msg{}
	msg.Unpack(data)
	return &msg
}
