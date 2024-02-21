package network

import (
	"Scanner/localtls"
	"Scanner/pkg/config"
	structs2 "Scanner/pkg/scanner/structs"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/smtp"
	"time"
)

type TLSRequest struct {
	ScannableIPAddresses []net.IP
	FilteredIPAddresses  []net.IP
	ResolvedIPAddresses  []net.IP
	Hostname             string
	Port                 string
	Type                 string // TLS or SMTP
}

// returned from multi-IP lookups per hostname (parallelized)
type TLSResult struct {
	IP                net.IP
	CipherSuites      []structs2.VersionSuitesRecord
	CertificateRecord structs2.CertificateRecord
	PeerCertificates  []*x509.Certificate
	RawC              []byte
	ConnectionSuccess bool
	Error             string
}

// returned from multi-hostname lookups (parallelized)
type TLSCombinedResult struct {
	CombinedRecord     structs2.TLSCombinedRecord
	Certificates       map[string][]*x509.Certificate
	OriginalTLSRequest TLSRequest
}

const HOSTNAME_SECOND_TIMEOUT = 15

// called by SMTP
func ParallelHostnameScan(requests []TLSRequest) map[string]structs2.MXSpecificData {
	allMXSpecificData := make(map[string]structs2.MXSpecificData, 0)

	numThreads := len(requests)
	fmt.Printf("Num hostnames/threads: %d\n", len(requests))
	numTasks := len(requests)

	tasks := make(chan TLSRequest, numTasks)
	promiseResponses := make(chan TLSCombinedResult, numTasks)

	for workerIndex := 0; workerIndex < numThreads; workerIndex++ {
		go HostnameScanWorker(tasks, promiseResponses)
	}

	for jobIndex := 0; jobIndex < numTasks; jobIndex++ {
		tasks <- requests[jobIndex]
	}

	for resultIndex := 0; resultIndex < numTasks; resultIndex++ {
		r := <-promiseResponses
		fmt.Printf("%s done (%d/%d)\n",
			net.JoinHostPort(r.OriginalTLSRequest.Hostname, r.OriginalTLSRequest.Port),
			resultIndex+1, numTasks)
		if _, ok := allMXSpecificData[r.OriginalTLSRequest.Hostname]; !ok {
			allMXSpecificData[r.OriginalTLSRequest.Hostname] = structs2.MXSpecificData{}
		}
		var mxSpecificData structs2.MXSpecificData
		mxSpecificData.IPPortToCertificates = make(map[string][]byte)
		mxSpecificData.MXTLSInformation = make(map[string]structs2.TLSCombinedRecord)
		mxSpecificData.MXMetaData = make(map[string]structs2.SMTPMetadata)
		allMXSpecificData[r.OriginalTLSRequest.Hostname] = mxSpecificData
		allMXSpecificData[r.OriginalTLSRequest.Hostname].MXTLSInformation[net.JoinHostPort(r.OriginalTLSRequest.Hostname, r.OriginalTLSRequest.Port)] = r.CombinedRecord
		for k, v := range r.Certificates {
			allMXSpecificData[r.OriginalTLSRequest.Hostname].IPPortToCertificates[k] = make([]byte, 0)
			for _, cert := range v {
				allMXSpecificData[r.OriginalTLSRequest.Hostname].IPPortToCertificates[k] =
					append(allMXSpecificData[r.OriginalTLSRequest.Hostname].IPPortToCertificates[k], cert.Raw...)
			}
		}
	}
	return allMXSpecificData
}

func HostnameScanWorker(requests <-chan TLSRequest, results chan<- TLSCombinedResult) {
	for r := range requests {
		combinedRecord, certificates := r.ParallelIPScan()
		combined := TLSCombinedResult{
			CombinedRecord:     combinedRecord,
			Certificates:       certificates,
			OriginalTLSRequest: r,
		}
		results <- combined
	}
}

// create threads to handle multiple IPs at once per hostname, called directly for TLS scans
func (request TLSRequest) ParallelIPScan() (structs2.TLSCombinedRecord, map[string][]*x509.Certificate) {
	// Query the CAA Records and format and store them if available
	caaRecords := ResolveCAARecord(request.Hostname)

	// Certificate chains (ip:port to certificate chain)
	certificateChains := make(map[string][]*x509.Certificate)

	serializedIPAddresses := structs2.SerializeIPAddresses(request.ScannableIPAddresses)
	// Certificate data
	certificateSHA256FingerprintMap := make(map[string][]byte)        // fingerprint : raw byte, calculates unique certificates
	certificateRecords := make(map[string]structs2.CertificateRecord) // ip : record, stores records
	// Error data
	tlsErrors := make(map[string]string) // ip : error, stores all errors
	// Cipher suite data
	cipherSuites := make(map[string][]structs2.VersionSuitesRecord, 0)

	numThreads := len(request.ScannableIPAddresses)
	numTasks := len(request.ScannableIPAddresses)

	tasks := make(chan net.IP, numTasks)
	promiseResponses := make(chan TLSResult, numTasks)

	for workerIndex := 0; workerIndex < numThreads; workerIndex++ {
		go IPScanWorker(request, tasks, promiseResponses)
	}

	for jobIndex := 0; jobIndex < numTasks; jobIndex++ {
		tasks <- request.ScannableIPAddresses[jobIndex]
	}

	for resultIndex := 0; resultIndex < numTasks; resultIndex++ {
		r := <-promiseResponses
		// If successful TLS connection to IP, store ciphersuites, certificate chain, and sha256 fingerprint
		if r.Error != "" {
			tlsErrors[r.IP.String()] = r.Error
		}
		if r.ConnectionSuccess {
			certificateRecords[r.IP.String()] = r.CertificateRecord
			cipherSuites[r.IP.String()] = r.CipherSuites
			certificateChains[net.JoinHostPort(r.IP.String(), request.Port)] = r.PeerCertificates
			if _, ok := certificateSHA256FingerprintMap[r.CertificateRecord.SHA256Fingerprint]; !ok {
				certificateSHA256FingerprintMap[r.CertificateRecord.SHA256Fingerprint] = r.RawC
			}
		}
	}

	// Begin assembling the response.
	record := structs2.TLSCombinedRecord{}
	record.Hostname = request.Hostname
	record.FilteredIPs = structs2.SerializeIPList(request.FilteredIPAddresses)
	record.ResolvedIPs = structs2.SerializeIPList(request.ResolvedIPAddresses)
	record.ScannedIPs = serializedIPAddresses.IPs
	record.IPv4Count = serializedIPAddresses.IPv4Count
	record.IPv6Count = serializedIPAddresses.IPv6Count
	record.NumUniqueCerts = len(certificateSHA256FingerprintMap)
	record.Certificates = certificateRecords
	record.Errors = tlsErrors
	record.CipherSuites = cipherSuites
	record.CAARecords = caaRecords

	return record, certificateChains
}

func CheckCertEVStatus(cert *x509.Certificate) structs2.EVCertInformation {
	extensions := cert.Extensions
	isEV := false
	evOID := ""
	org := ""
	for _, ext := range extensions {
		asn1OIDString := ext.Id.String()
		if val, ok := localtls.EVObjectIdentifiers[asn1OIDString]; ok {
			isEV = true
			evOID = asn1OIDString
			org = val
			break
		}
	}
	return structs2.EVCertInformation{
		IsEVCertType:        isEV,
		ObjectIdentifier:    evOID,
		IssuingOrganization: org,
	}
}

// individual thread worker (responsible for retrieving cipher suites + certificate info)
func IPScanWorker(request TLSRequest, ips <-chan net.IP, results chan<- TLSResult) {
	for IP := range ips {
		res := TLSResult{IP: IP, ConnectionSuccess: true}
		// nil if no validation error, set to error otherwise
		clientConfig := tls.Config{
			ServerName:         request.Hostname,
			InsecureSkipVerify: true,
			VerifyConnection:   nil,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}

		var certValid bool
		var certErr error
		var c *x509.Certificate
		// Gather certificate info
		statusRecord := structs2.StatusRecord{}

		chain := make([]structs2.ChainRecord, 0)
		// switch statement which handles differences between TLS and SMTP
		switch request.Type {
		case "SMTP":
			dialer := &net.Dialer{
				Timeout: HOSTNAME_SECOND_TIMEOUT * time.Second,
			}
			conn, err := dialer.Dial("tcp", net.JoinHostPort(IP.String(), request.Port))
			if err != nil {
				res.ConnectionSuccess = false
				results <- res
				continue
			}
			conn.SetDeadline(time.Now().Add(time.Second * config.TLS_CIPHER_SUITE_SECOND_TIMEOUT))

			smtpConn, err := smtp.NewClient(conn, request.Hostname)
			if err != nil {
				res.ConnectionSuccess = false
				results <- res
				continue
			}

			smtpConn.Hello(config.SMTPHELO_Introduction)

			connErr := smtpConn.StartTLS(&clientConfig)
			if connErr != nil {
				res.ConnectionSuccess = false
				results <- res
				continue
			}
			// Gather suite info
			res.CipherSuites = RetrieveCipherSuites(IP, request.Hostname, request.Port, request.Type)

			connState, ok := smtpConn.TLSConnectionState()
			if ok {
				certValid, certErr := VerifyTLSConnection(connState)
				if certErr != nil {
					statusRecord.Err = certErr.Error()
				} else {
					statusRecord.Err = ""
				}
				statusRecord.Valid = certValid
			} else {
				statusRecord.Err = "failed to create a TLS connection"
				statusRecord.Valid = false
			}

			// save certificate chain for TLSA verification
			res.PeerCertificates = connState.PeerCertificates

			c = connState.PeerCertificates[0]
			// create chain of parent certificates
			chain := make([]structs2.ChainRecord, 0)

			for _, parentCertificate := range connState.PeerCertificates[1:] {
				sha256Fingerprint := sha256.Sum256(parentCertificate.Raw)
				keyType, keyLength := structs2.IdentifyPublicKeyType(parentCertificate.PublicKey)
				chain = append(chain, structs2.ChainRecord{
					Issuer:             parentCertificate.Issuer.String(),
					Fingerprint:        hex.EncodeToString(sha256Fingerprint[:]),
					KeyType:            keyType,
					KeyLength:          keyLength,
					SignatureAlgorithm: parentCertificate.SignatureAlgorithm.String(),
					IsCA:               parentCertificate.IsCA,
				})
			}
		case "TLS":
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: HOSTNAME_SECOND_TIMEOUT * time.Second}, "tcp", net.JoinHostPort(IP.String(), request.Port), &clientConfig)
			if err != nil {
				res.Error = err.Error()
				res.ConnectionSuccess = false
				results <- res
				continue
			}

			tlsConnectionState := conn.ConnectionState()
			certValid, certErr = VerifyTLSConnection(tlsConnectionState)

			if certErr == nil {
				statusRecord.Err = ""
			} else {
				statusRecord.Err = certErr.Error()
			}
			statusRecord.Valid = certValid

			// Gather suite info
			res.CipherSuites = RetrieveCipherSuites(IP, request.Hostname, request.Port, request.Type)
			// Gather certificate info
			res.PeerCertificates = conn.ConnectionState().PeerCertificates

			c = conn.ConnectionState().PeerCertificates[0]
			// create chain of parent certificates
			for _, parentCertificate := range conn.ConnectionState().PeerCertificates[1:] {
				sha256Fingerprint := sha256.Sum256(parentCertificate.Raw)
				// danetlsa := dane.ComputeTLSA(0, 0, parentCertificate)
				keyType, keyLength := structs2.IdentifyPublicKeyType(parentCertificate.PublicKey)
				chain = append(chain, structs2.ChainRecord{
					Issuer:             parentCertificate.Issuer.String(),
					Fingerprint:        hex.EncodeToString(sha256Fingerprint[:]),
					KeyType:            keyType,
					KeyLength:          keyLength,
					SignatureAlgorithm: parentCertificate.SignatureAlgorithm.String(),
					IsCA:               parentCertificate.IsCA,
				})
			}
			conn.Close()
		}

		record := structs2.CertificateRecord{}
		record.Subject = c.Subject.String()
		record.CommonName = c.Subject.CommonName
		record.AlternateNames = c.DNSNames
		record.SerialNumber = c.SerialNumber.String()
		record.From = c.NotBefore
		record.Until = c.NotAfter
		record.KeyType, record.KeyLength = structs2.IdentifyPublicKeyType(c.PublicKey)
		record.PublicKey = structs2.SerializePublicKey(c.PublicKey)
		record.Issuer = c.Issuer.String()
		record.SignatureAlgorithm = c.SignatureAlgorithm.String()
		record.EV = CheckCertEVStatus(c)

		record.Status = statusRecord

		record.Chain = chain

		// check for duplicate certificate
		sha256Fingerprint := sha256.Sum256(c.Raw)
		strSha256Fingerprint := hex.EncodeToString(sha256Fingerprint[:])
		record.SHA256Fingerprint = strSha256Fingerprint

		sha1Fingerprint := sha1.Sum(c.Raw)
		record.SHA1Fingerprint = hex.EncodeToString(sha1Fingerprint[:])

		record.KeyUsage = structs2.SerializeKeyUsage(c.KeyUsage)
		record.ExtKeyUsage = structs2.SerializeExtendedKeyUsage(c.ExtKeyUsage)

		SPKIFingerprint := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		record.SPKISHA256Hash = hex.EncodeToString(SPKIFingerprint[:])
		// new certificate check
		res.RawC = c.Raw

		// error check
		if certErr != nil {
			res.Error = certErr.Error()
		}
		res.CertificateRecord = record
		results <- res
	}
}
