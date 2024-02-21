package structs

import "time"

type CertificateRecord struct {
	Subject            string                 `json:"subject"`
	CommonName         string                 `json:"cn"` // Serializes as per RFC 2253
	AlternateNames     []string               `json:"san"`
	SerialNumber       string                 `json:"serialNumber"` // Decimal representation Base10 OF BigInt
	From               time.Time              `json:"validFrom"`
	Until              time.Time              `json:"validUntil"`
	KeyType            PublicKeyType          `json:"publicKeyType"`
	PublicKey          string                 `json:"publicKey"`       // Hex encoded
	KeyLength          int                    `json:"publicKeyLength"` // Length of byte array
	Issuer             string                 `json:"issuer"`          // Serializes as per RFC 2253
	SignatureAlgorithm string                 `json:"signatureAlgorithm"`
	EV                 EVCertInformation      `json:"ev"`
	Status             StatusRecord           `json:"status"`
	Chain              []ChainRecord          `json:"chain"`
	SHA256Fingerprint  string                 `json:"sha256fingerprint"` // Hex encoded
	SHA1Fingerprint    string                 `json:"sha1fingerprint"`   // Hex encoded
	KeyUsage           []KeyUsageType         `json:"keyUsage"`
	ExtKeyUsage        []ExtendedKeyUsageType `json:"extKeyUsage"`
	SPKISHA256Hash     string                 `json:"spkiHash"` // Hex encoded
}

type ChainRecord struct {
	Issuer             string        `json:"issuer"`
	Fingerprint        string        `json:"sha256fingerprint"`
	KeyType            PublicKeyType `json:"publicKeyType"`
	KeyLength          int           `json:"publicKeyLength"`
	SignatureAlgorithm string        `json:"signatureAlgorithm"`
	IsCA               bool          `json:"isCA"`
}

type EVCertInformation struct {
	IsEVCertType        bool   `json:"isEV"`
	ObjectIdentifier    string `json:"oid"`
	IssuingOrganization string `json:"org"`
}
