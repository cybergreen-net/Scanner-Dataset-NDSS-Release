package network

import (
	"Scanner/pkg/scanner/structs"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/vodkaslime/wildcard"
)

var (
	ErrUnresolvedHTTPSMTASTS = errors.New("E_HTTPS_MTA-STS_NOEXIST")
	ErrUnresolvedDNSMTASTS   = errors.New("E_DNS_MTA-STS_NOEXIST")
	ErrUnresolvedMTASTS      = errors.New("E_MTA-STS_NOEXIST")
)

type MTASTS struct {
	Hostname             string
	MXRecordsForHostname []string
}

func parseByteArrIntoMTASTSRecord(bytes []byte) structs.HTTPSRecord {
	str := string(bytes)
	str = strings.ReplaceAll(str, "\r\n", "\n")
	str = strings.Trim(str, "\n")
	foundErrors := make([]string, 0)
	r := structs.HTTPSRecord{}
	for _, line := range strings.Split(str, "\n") {
		keyValue := strings.Split(line, ": ")
		if len(keyValue) != 2 {
			foundErrors = append(foundErrors, "malformed key value pair")
			continue
		}
		switch keyValue[0] {
		case "version":
			r.Version = keyValue[1]
		case "mode":
			r.Mode = keyValue[1]
		case "mx":
			r.AllowedMXPatterns = append(r.AllowedMXPatterns, keyValue[1])
		case "max_age":
			maxAge, parseIntError := strconv.Atoi(keyValue[1])
			if parseIntError != nil {
				foundErrors = append(foundErrors, "could not parse max_int value")
			} else {
				r.MaxAge = maxAge
			}
		default:
			r.Extensions = append(r.Extensions, structs.Pair{Key: keyValue[0], Value: keyValue[1]})
		}
	}
	// MTA-STS must contain version, mode, max_age, and at least one MX field
	if r.Version == "" {
		foundErrors = append(foundErrors, "no MTA-STS version found (required)")
	}

	if r.Mode == "" {
		foundErrors = append(foundErrors, "no MTA-STS mode found (required)")
	}

	if r.MaxAge == 0 {
		foundErrors = append(foundErrors, "no MTA-STS max age found (required)")
	}

	if len(r.AllowedMXPatterns) == 0 {
		foundErrors = append(foundErrors, "no MTA-STS allowed MX patterns found (at least one required)")
	}
	r.Errors = foundErrors
	return r
}

func getPolicyInformationFromHTTPS(httpClient *http.Client, hostname string) (structs.HTTPSRecord, bool) {
	record := structs.HTTPSRecord{}

	// MTA-STS records retrieved under https://mta-sts.[hostname]/.well-known/mta-sts.txt
	requestURL := fmt.Sprintf("https://%s.%s/%s", MTA_STS_HTTPS_PREFIX, hostname, MTA_STS_HTTPS_POLICY_LOCATION)
	res, err := httpClient.Get(requestURL)

	if err != nil {
		record.Errors = append(record.Errors, fmt.Sprintf("unable to connect to mta-sts hostname: %v", err))
		return record, false
	}
	// 	MTA-STS must be OK 200/HTTP 3XX must not be followed
	if res.StatusCode != 200 {
		record.Errors = append(record.Errors, fmt.Sprintf("status code expected [200] != [%v]", res.StatusCode))
		return record, true
	}

	bodyBuffer, err := io.ReadAll(res.Body)
	if err != nil {
		record.Errors = append(record.Errors, fmt.Sprintf("couldn't read mta-sts response body: %v", err))
		return record, true
	}

	// MTA-STS must be of content type "text/plain"
	contentType := http.DetectContentType(bodyBuffer)
	if !strings.Contains(contentType, "text/plain") {
		record.Errors = append(record.Errors, "content type was not text/plain")
		return record, true
	}

	record = parseByteArrIntoMTASTSRecord(bodyBuffer)
	return record, true
}

func ValidateMTASTSRecordMatches(policyRecords structs.HTTPSRecord, mxRecords []string) []structs.MTASTSPolicyValidity {
	results := make([]structs.MTASTSPolicyValidity, 0)

	allowedPolicyMXPatternMatches := policyRecords.AllowedMXPatterns

	mxValidityMap := make(map[string]bool)

	for _, mxHost := range mxRecords {
		host := strings.ToLower(dns.Fqdn(mxHost))

		for _, pattern := range allowedPolicyMXPatternMatches {
			matcher := wildcard.NewMatcher()
			match, err := matcher.Match(dns.Fqdn(pattern), host)
			if err != nil {
				continue
			}
			if match {
				if _, ok := mxValidityMap[host]; !ok {
					mxValidityMap[host] = match
				}
				break
			}
		}
	}

	for _, host := range mxRecords {
		hostLower := strings.ToLower(dns.Fqdn(host))
		if hostValidity, ok := mxValidityMap[hostLower]; ok {
			results = append(results, structs.MTASTSPolicyValidity{Valid: hostValidity, Hostname: host})
		}
	}

	return results
}

func (m MTASTS) Query() structs.MTASTSRecord {
	record := structs.MTASTSRecord{}

	httpClient := &http.Client{
		Transport: &http.Transport{
			IdleConnTimeout: 60 * time.Second,
		},
		Timeout: 60 * time.Second,
	}
	// httpExists set to false if HTTPS lookup is unresolved
	mtaHTTPSRecord, httpExists := getPolicyInformationFromHTTPS(httpClient, m.Hostname)
	// dnsExists set to false if length of retrieved records is 0
	mtaDNSRecord, dnsExsits := ResolveMTASTSDNSRecord(m.Hostname)

	record.HTTPSRecord = mtaHTTPSRecord
	record.MTATextRecord = mtaDNSRecord
	if !httpExists {
		record.HTTPSRecord = ErrUnresolvedHTTPSMTASTS.Error()
	}

	if !dnsExsits {
		record.MTATextRecord = ErrUnresolvedDNSMTASTS.Error()
	}

	record.ValidRecords = make([]structs.MTASTSPolicyValidity, 0)
	if httpExists && dnsExsits {
		record.ValidRecords = ValidateMTASTSRecordMatches(mtaHTTPSRecord, m.MXRecordsForHostname)
	}

	return record
}
