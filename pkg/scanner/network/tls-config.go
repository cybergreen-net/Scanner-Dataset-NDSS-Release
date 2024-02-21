package network

import (
	"crypto/tls"
	"crypto/x509"
)

// VerifyTLSConnection Explicit Verification Method for the TLS connection
func VerifyTLSConnection(cs tls.ConnectionState) (bool, error) {
	opts := x509.VerifyOptions{
		DNSName:       cs.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := cs.PeerCertificates[0].Verify(opts)
	if err != nil {
		return false, err
	}
	return true, nil
}
