package network

import (
	"Scanner/pkg/scanner/network"
	"Scanner/pkg/scanner/structs"
	"testing"
)

func TestValidateMTASTSRecordMatches(t *testing.T) {
	mtastsPatterns := []string{
		"gmail-smtp-in.l.google.com",   // Regular MX Pattern
		"mx1.cs.washington.edu.",       // FQDN MX Pattern
		"*.mx.cs.washington.edu.",      // FQDN Wildcard MX Pattern
		"*.gmail-smtp-in.l.google.com", // Wildcard MX Pattern
	}
	invalidHost := "abc.gmail-smtp-in.I.google.com" // Replace l => I

	mxHosts := []string{
		"mx1.cs.washington.edu.",
		"mxa1.mx.cs.washington.edu.",
		"gmail-smtp-in.l.google.com.",
		"alt1.gmail-smtp-in.l.google.com.",
		"alt2.gmail-smtp-in.l.google.com.",
		"alt3.gmail-smtp-in.l.google.com.",
		"alt4.gmail-smtp-in.l.google.com.",
	}

	policyRecord := structs.HTTPSRecord{
		Version:           "STSv1",
		Mode:              "enforce",
		MaxAge:            60000,
		AllowedMXPatterns: mtastsPatterns,
		Errors:            []string{},
		Extensions:        nil,
	}

	validHosts := network.ValidateMTASTSRecordMatches(policyRecord, mxHosts)
	invalidHosts := network.ValidateMTASTSRecordMatches(policyRecord, []string{invalidHost})

	if len(validHosts) != len(mxHosts) {
		t.Error("failed to validate the hosts with the pattern. This test should have passed.")
	}
	if len(invalidHosts) != 0 {
		t.Error("an invalid host not matching the patterns passed validation check. Should fail instead.")
	}
	for _, validHost := range validHosts {
		if !validHost.Valid {
			t.Error("an invalid host match made it into the valid hosts response. Response should have been valid.")
		}
	}
}
