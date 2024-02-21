package structs

import (
	"sort"
	"strconv"
	"strings"
)

type MailScanCombinedRecord struct {
	MailHost             string                                  `json:"mailHost"`
	ResolvedMX           []string                                `json:"mxServers"`
	MXServerPriority     map[string]uint16                       `json:"mxServerPriority"`
	MXServerReachability map[string]ReachabilitySecurityMetadata `json:"mxServerReachability"`
	NumResolvedMX        int                                     `json:"numMxServers"`
	MailServerMetadata   map[string]SMTPMetadata                 `json:"metadata"`
	MXTLSInformation     map[string]TLSCombinedRecord            `json:"mxTLSInformation"`
}

type SMTPMetadata struct {
	// private scope
	host string
	// public scope
	Banner       string            `json:"banner"`
	Capabilities map[string]string `json:"capabilities"`
}

func (s *SMTPMetadata) GetHost() string {
	return s.host
}

func NewSMTPMetadata(address string) SMTPMetadata {
	return SMTPMetadata{host: address}
}

type ReachabilitySecurityMetadata struct {
	SecurePorts    []int `json:"secure"`
	ReachablePorts []int `json:"reachable"`
}

func identifyAllowedPorts[V SMTPMetadata | TLSCombinedRecord](input map[string]V) map[string]map[int]bool {
	mxPortMap := make(map[string]map[int]bool)

	for mx, _ := range input {
		mxSegments := strings.Split(mx, ":")
		if len(mxSegments) == 2 {
			mxHost := mxSegments[0]
			port, _ := strconv.Atoi(mxSegments[1])
			portExistenceMap, ok := mxPortMap[mxHost]

			if !ok {
				portExistenceMap = make(map[int]bool)
				portExistenceMap[port] = true
				mxPortMap[mxHost] = portExistenceMap
			}
			if ok {
				_, portOk := portExistenceMap[port]
				if !portOk {
					portExistenceMap[port] = true
					mxPortMap[mxHost] = portExistenceMap
				}
			}
		}
	}

	return mxPortMap
}

func (m *MailScanCombinedRecord) IdentifyReachableAndSecurePorts() {
	result := make(map[string]ReachabilitySecurityMetadata)

	mxReachablePorts := identifyAllowedPorts(m.MailServerMetadata)
	mxSecurePorts := identifyAllowedPorts(m.MXTLSInformation)

	uniqueMxServers := make(map[string]bool)
	for _, portData := range []map[string]map[int]bool{mxReachablePorts, mxSecurePorts} {
		for mx, _ := range portData {
			if _, ok := uniqueMxServers[mx]; !ok {
				uniqueMxServers[mx] = true
			}
		}
	}

	for mx, _ := range uniqueMxServers {
		response := ReachabilitySecurityMetadata{}
		securePortMap, securePortOk := mxSecurePorts[mx]
		securePorts := make([]int, 0)
		if securePortOk {
			for port, _ := range securePortMap {
				securePorts = append(securePorts, port)
			}
		}

		reachablePortMap, reachablePortOk := mxReachablePorts[mx]
		reachablePorts := make([]int, 0)
		if reachablePortOk {
			for port, _ := range reachablePortMap {
				reachablePorts = append(reachablePorts, port)
			}
		}

		sort.Ints(securePorts)
		sort.Ints(reachablePorts)

		response.ReachablePorts = reachablePorts
		response.SecurePorts = securePorts

		result[mx] = response
	}

	m.MXServerReachability = result
}
