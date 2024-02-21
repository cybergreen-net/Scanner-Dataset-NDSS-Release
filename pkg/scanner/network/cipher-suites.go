package network

import (
	"Scanner/localtls"
	"Scanner/pkg/config"
	"Scanner/pkg/scanner/structs"
	"crypto/tls"
	"net"
	"net/smtp"
	"time"
)

type CipherSuiteRequest struct {
	TLSVersion     uint16
	TLSCipherSuite uint16
}

type CipherSuiteResponse struct {
	TLSVersion     uint16
	TLSCipherSuite uint16
	Successful     bool
}

func RetrieveCipherSuites(ip net.IP, hostname string, port string, connectionType string) []structs.VersionSuitesRecord {
	versionSuitesRecordArr := make([]structs.VersionSuitesRecord, 0)
	cipherSuiteRequests := make([]CipherSuiteRequest, 0)
	for _, v := range localtls.TLSVersions {
		switch v {
		case tls.VersionTLS10, tls.VersionTLS11:
			cipherSuiteRequests = append(cipherSuiteRequests, CreateCipherSuiteRequests(v, localtls.TLSUniversalCiphers)...)
		case tls.VersionTLS12:
			cipherSuiteRequests = append(cipherSuiteRequests, CreateCipherSuiteRequests(v, localtls.TLS12Ciphers)...)
		case tls.VersionTLS13:
			cipherSuiteRequests = append(cipherSuiteRequests, CreateCipherSuiteRequests(v, localtls.TLS13Ciphers)...)
		}
	}
	numTasks := len(cipherSuiteRequests)
	requests := make(chan CipherSuiteRequest, numTasks)
	responses := make(chan CipherSuiteResponse, numTasks)
	for i := 0; i < config.CIPHER_SUITE_WORKER_COUNT; i++ {
		go CipherSuiteWorker(requests, responses, ip, hostname, port, connectionType)
	}

	for _, req := range cipherSuiteRequests {
		requests <- req
	}

	versionCipherSuiteMap := make(map[uint16][]uint16)
	for i := 0; i < numTasks; i++ {
		res := <-responses
		if _, ok := versionCipherSuiteMap[res.TLSVersion]; !ok {
			versionCipherSuiteMap[res.TLSVersion] = make([]uint16, 0)
		}
		if res.Successful {
			versionCipherSuiteMap[res.TLSVersion] = append(versionCipherSuiteMap[res.TLSVersion], res.TLSCipherSuite)
		}
	}

	for _, v := range localtls.TLSVersions {
		versionSuitesRecord := structs.VersionSuitesRecord{TLSVersion: v, SupportedCipherSuites: versionCipherSuiteMap[v]}
		if len(versionSuitesRecord.SupportedCipherSuites) > 0 {
			versionSuitesRecord.IsSupported = true
		}
		versionSuitesRecordArr = append(versionSuitesRecordArr, versionSuitesRecord)
	}
	return versionSuitesRecordArr
}

func CreateCipherSuiteRequests(tlsVersion uint16, cipherSuites []uint16) []CipherSuiteRequest {
	cipherSuiteRequests := make([]CipherSuiteRequest, 0)
	for _, cs := range cipherSuites {
		cipherSuiteRequests = append(cipherSuiteRequests, CipherSuiteRequest{TLSVersion: tlsVersion, TLSCipherSuite: cs})
	}
	return cipherSuiteRequests
}

func CipherSuiteWorker(cipherSuiteRequests <-chan CipherSuiteRequest,
	cipherSuiteResponses chan<- CipherSuiteResponse,
	ip net.IP, hostname string, port string, connectionType string) {
	for req := range cipherSuiteRequests {
		c := req.TLSCipherSuite
		v := req.TLSVersion
		cfg := &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true,
			VerifyConnection:   nil,
			CipherSuites:       []uint16{c},
			MinVersion:         v,
			MaxVersion:         v,
		}
		switch connectionType {
		case "SMTP":
			dialer := &net.Dialer{
				Timeout: config.TLS_CIPHER_SUITE_SECOND_TIMEOUT * time.Second,
			}
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ip.String(), port))
			if err != nil {
				cipherSuiteResponses <- CipherSuiteResponse{TLSVersion: v, TLSCipherSuite: c, Successful: false}
				continue
			}
			conn.SetDeadline(time.Now().Add(time.Second * config.TLS_CIPHER_SUITE_SECOND_TIMEOUT))
			smtpConn, err := smtp.NewClient(conn, hostname)
			if err != nil {
				cipherSuiteResponses <- CipherSuiteResponse{TLSVersion: v, TLSCipherSuite: c, Successful: false}
				continue
			}
			smtpConn.Hello(config.SMTPHELO_Introduction)

			connErr := smtpConn.StartTLS(cfg)
			if connErr != nil {
				cipherSuiteResponses <- CipherSuiteResponse{TLSVersion: v, TLSCipherSuite: c, Successful: false}
				continue
			}

			clientState, ok := smtpConn.TLSConnectionState()

			// Append supported cipher suite for
			if ok && clientState.CipherSuite == c {
				cipherSuiteResponses <- CipherSuiteResponse{TLSVersion: v, TLSCipherSuite: c, Successful: true}
				continue
			}
			cipherSuiteResponses <- CipherSuiteResponse{TLSVersion: v, TLSCipherSuite: c, Successful: false}

			conn.Close()
		case "TLS":
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: config.TLS_CIPHER_SUITE_SECOND_TIMEOUT * time.Second}, "tcp", net.JoinHostPort(ip.String(), port), cfg)
			if err != nil {
				cipherSuiteResponses <- CipherSuiteResponse{TLSVersion: v, TLSCipherSuite: c, Successful: false}
				continue
			}
			// Append supported cipher suite for
			if conn.ConnectionState().CipherSuite == c {
				cipherSuiteResponses <- CipherSuiteResponse{TLSVersion: v, TLSCipherSuite: c, Successful: true}
				continue
			}
			conn.Close()
			cipherSuiteResponses <- CipherSuiteResponse{TLSVersion: v, TLSCipherSuite: c, Successful: false}
		}

	}
}
