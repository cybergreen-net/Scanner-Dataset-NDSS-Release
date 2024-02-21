package structs

type MXSpecificData struct {
	MXTLSInformation     map[string]TLSCombinedRecord `json:"mxTLSInformation"`
	MXMetaData           map[string]SMTPMetadata      `json:"mxMetaData"`
	IPPortToCertificates map[string][]byte            `json:"ipPortToCertificates"`
	// Unique Fingerprint
	PortCount           int `json:"portCount"`
	TLSVersionCount     int `json:"tlsVersionCount"`
	TLSCipherSuiteCount int `json:"tlsCipherSuiteCount"`
	// Cache Count
	SeenCount int `json:"mxSeenCount"`
}

// Returns negative num for less than, 0 for equal, positive num for greater than
func (m MXSpecificData) CompareTo(o MXSpecificData) int {
	if m.PortCount != o.PortCount {
		return m.PortCount - o.PortCount
	} else if m.TLSVersionCount != o.TLSVersionCount {
		return m.TLSVersionCount - o.TLSVersionCount
	} else if m.TLSCipherSuiteCount != o.TLSCipherSuiteCount {
		return m.TLSCipherSuiteCount - o.TLSCipherSuiteCount
	} else {
		return 0
	}
}
