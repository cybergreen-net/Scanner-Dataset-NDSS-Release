package structs

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/shuque/dane"
	"github.com/zmap/go-iptree/iptree"
)

type MailScanCombinedRecord struct {
	MailHost             string                                  `json:"mailHost"`
	ResolvedMX           []string                                `json:"mxServers"`
	MXServerPriority     map[string]uint16                       `json:"mxServerPriority"`
	MXServerReachability map[string]ReachabilitySecurityMetadata `json:"mxServerReachability"`
	NumResolvedMX        int                                     `json:"numMxServers"`
	MailServerMetadata   map[string]SMTPMetadata                 `json:"metadata"`
	MXTLSInformation     map[string]TLSCombinedRecord            `json:"mxTLSInformation"`
	MXTLSAInformation    map[string]interface{}                  `json:"mxTLSAInformation"`
	MTASTS               MTASTSRecord                            `json:"mta-sts"`
	SPF                  CombinedSPFRecord                       `json:"spf"`
	DMARC                DMARCRecord                             `json:"dmarc"`
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

// Holds TLSA record results, based on port and hostname
type TLSARecord struct {
	TLSARecordExists bool              `json:"tlsaRecordExists"`
	ValidIPs         []string          `json:"tlsaValidIPs"`
	InvalidIPs       map[string]string `json:"tlsaInvalidIPs"`
	Usage            int               `json:"tlsaUsage"`
	Selector         int               `json:"tlsaSelector"`
	MatchType        int               `json:"matchType"`
	// TODO: Get the TLSA specific information (Usage, Selector, Match Type)
	// TODO: Valid IP of mail servers which match TLSA records
	// TODO: Invalid IPs of mail servers which match TLSA records, and invalidity reason
}

type TLSAStatusIP struct {
	Verified bool   `json:"verified"` // matches a TLSA record
	Error    string `json:"error"`
}
type MTASTSRecord struct {
	HTTPSRecord   interface{}            `json:"policy"` // Comes from the HTTPS .well-known endpoint
	MTATextRecord interface{}            `json:"record"` // Comes from DNS
	ValidRecords  []MTASTSPolicyValidity `json:"validRecords"`
}

type HTTPSRecord struct {
	Version           string   `json:"version"`
	Mode              string   `json:"mode"`
	MaxAge            int      `json:"maxAge"`
	AllowedMXPatterns []string `json:"allowedMXPatterns"`
	Errors            []string `json:"errors"`
	Extensions        []Pair   `json:"extensions"`
}

type MTATextRecord struct {
	Version    string   `json:"version"`
	ID         string   `json:"id"`
	Extensions []Pair   `json:"extensions"`
	HasCNAME   bool     `json:"hasCNAME"`
	Errors     []string `json:"errors"`
	Valid      bool     `json:"valid"`
}

type Pair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type MTASTSPolicyValidity struct {
	Hostname string `json:"hostname"`
	Valid    bool   `json:"valid"`
}

// a struct to store TLSA records (in the form of dane.config structs) until smtp.scan is complete
type TLSAContainer struct {
	TLSARecord *dane.TLSAinfo
	Error      string
}

// Result of SPF check
type SPFResult struct {
	Type             string               `json:"type"`             // redirect or include
	SPFText          string               `json:"spfText"`          // raw SPF text
	SimpleLookupIPs  []string             `json:"simpleLookupIPs"`  // all IPs from simple lookups
	SimpleLookups    []SimpleLookup       `json:"simpleLookups"`    // for macro, A, AAAA, MX, format: (host/IP -> IP(s), type, error, spfqualifier)
	RecursiveLookups map[string]SPFResult `json:"recursiveLookups"` // redirect or include (host -> SPFRes)
	AllQualifier     EvaluationQuantifier `json:"allQualifier"`     // pass, neutral, fail, softfail
	SPFError         SPFError             `json:"lookupError"`      // None (no record found), TempError (dns lookup temp failure), PermError (spf structure issue)
}

type SimpleLookup struct {
	LookupType           string               `json:"lookupType"`
	Parameter            string               `json:"parameter"`
	IPs                  []string             `json:"ips"`
	Pointer              string               `json:"ptr"`
	EvaluationQuantifier EvaluationQuantifier `json:"lookupQualifier"`
	SPFError             SPFError             `json:"lookupError"` // None (no record found), TempError (dns lookup temp failure), PermError (spf structure issue)

}

type CombinedSPFRecord struct {
	SPFVersion                  string                     `json:"spfVersion"`
	SPFErrors                   []SPFError                 `json:"lookupErrors"` // None (no record found), TempError (dns lookup temp failure), PermError (spf structure issue)
	SPFIPs                      []string                   `json:"spfIPs"`
	Depth                       int                        `json:"depth"`
	SPFResult                   SPFResult                  `json:"spfResult"`
	SPFPolicyCheck              map[string]map[string]bool `json:"spfPolicyCheck"`
	PermissivePolicyEnforcement bool                       `json:"permissiveSPFPolicyCheck"`
	StrictPolicyEnforcement     bool                       `json:"strictSPFPolicyCheck"`
}

func (c *CombinedSPFRecord) ValidatePolicy(scannedMailServerIPs map[string][]net.IP) {
	c.SPFPolicyCheck = validateSPFPolicyByMailServer(c.SPFIPs, scannedMailServerIPs)
	policies := make([]bool, 0)
	for _, ip_spf_validity := range c.SPFPolicyCheck {
		for _, validity := range ip_spf_validity {
			policies = append(policies, validity)
		}
	}
	if len(policies) == 0 {
		c.PermissivePolicyEnforcement = false
		c.StrictPolicyEnforcement = false
	} else {
		permissivePolicyCheck := policies[0]
		strictPolicyCheck := policies[0]
		remainingPolicies := policies[1:]
		for _, policyValidity := range remainingPolicies {
			permissivePolicyCheck = permissivePolicyCheck || policyValidity
			strictPolicyCheck = strictPolicyCheck && policyValidity
		}
		c.PermissivePolicyEnforcement = permissivePolicyCheck
		c.StrictPolicyEnforcement = strictPolicyCheck
	}
}

/*
 *
 * Note: This validation procedure assumes that the MX server and associated IPs are the ones which send the mail servers.
 * The MXes are typically used for incoming email but mail infrastructure providers can configure incoming and outgoing
 * emails through different IPs because of various IP reputation concerns. Since it is not possible to validate SPF Policy
 * without receiving an email from the intended host, we use the MX server IPs as an approximation for the sender IPs to
 * validate the SPF records against.
 */
func validateSPFPolicyByMailServer(spfIPs []string, mailServerIPs map[string][]net.IP) map[string]map[string]bool {
	result := make(map[string]map[string]bool)

	ipTree := iptree.New()
	for _, spfIP := range spfIPs {
		err := ipTree.AddByString(spfIP, 0)
		if err != nil {
			continue
		}
	}

	for mxHost, mxSenderIPs := range mailServerIPs {
		mailServerIPToValidityResult := make(map[string]bool)
		for _, senderIP := range mxSenderIPs {
			_, exists, _ := ipTree.Get(senderIP)
			mailServerIPToValidityResult[senderIP.String()] = exists
		}
		result[mxHost] = mailServerIPToValidityResult
	}

	return result
}

type EvaluationQuantifier string

type SPFError string

// SPF results
const (
	Neutral  = EvaluationQuantifier("NEUTRAL")  // if IP matches, neutral behavior
	Pass     = EvaluationQuantifier("PASS")     // if IP matches, pass
	Fail     = EvaluationQuantifier("FAIL")     // if IP matches, fail
	Softfail = EvaluationQuantifier("SOFTFAIL") // if IP matches, fail softly
)

const (
	None                  = SPFError("NONE")                  // no record
	TempError             = SPFError("TEMPERROR")             // temporary error contacting DNS
	PermError             = SPFError("PERMERROR")             // syntactical error/permanent error
	PermError_LookupCount = SPFError("PERMERROR_LookupCount") // syntactical error/permanent error
)

// String representation of SPFIfMatch type
func (r EvaluationQuantifier) String() string {
	return string(r)
}

// String representation of SPFIfMatch type
func (r SPFError) String() string {
	return string(r)
}

// IsSet returns true if Result var is set to some value
func (r SPFError) IsSet() bool {
	return string(r) != ""
}
