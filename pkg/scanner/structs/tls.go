package structs

type TLSCombinedRecord struct {
	Hostname       string                           `json:"hostname"`
	ResolvedIPs    []string                         `json:"resolvedIPs"`
	ScannedIPs     []string                         `json:"scannedIPs"`
	FilteredIPs    []string                         `json:"filteredIPs"`
	IPv4Count      int                              `json:"ipv4count"`
	IPv6Count      int                              `json:"ipv6count"`
	NumUniqueCerts int                              `json:"numUniqueCerts"`
	Certificates   map[string]CertificateRecord     `json:"certificate"`  // ip : tlsrecord
	Errors         map[string]string                `json:"errors"`       // ip : error
	CipherSuites   map[string][]VersionSuitesRecord `json:"cipherSuites"` // ip : []VersionAndCipherSuites
}

type VersionSuitesRecord struct {
	TLSVersion            uint16   `json:"tlsVersion"`
	IsSupported           bool     `json:"isSupported"`
	SupportedCipherSuites []uint16 `json:"supportedCipherSuites"`
}
