package network

import (
	"Scanner/pkg/scanner/structs"
	"github.com/emersion/go-msgauth/dmarc"
)

type DMARC struct {
	Hostname string
}

func translateFailureOption(option dmarc.FailureOptions) string {
	if option == dmarc.FailureAll {
		return "0"
	}
	if option == dmarc.FailureAny {
		return "1"
	}
	if option == dmarc.FailureDKIM {
		return "d"
	}
	if option == dmarc.FailureSPF {
		return "s"
	}
	return "none"
}

func (m DMARC) LookupDMARCRecords() structs.DMARCRecord {
	result := structs.DMARCRecord{}
	dmarcResponse, err := dmarc.Lookup(m.Hostname)
	if err != nil {
		return result
	}
	result.DKIMAlignment = dmarcResponse.DKIMAlignment
	result.SPFAlignment = dmarcResponse.SPFAlignment
	result.FailureOptions = translateFailureOption(dmarcResponse.FailureOptions)
	result.Policy = dmarcResponse.Policy
	result.Percent = dmarcResponse.Percent
	result.ReportFormat = dmarcResponse.ReportFormat
	result.ReportInterval = dmarcResponse.ReportInterval
	result.ReportURIAggregate = dmarcResponse.ReportURIAggregate
	result.ReportURIFailure = dmarcResponse.ReportURIFailure
	result.SubdomainPolicy = dmarcResponse.SubdomainPolicy
	return result
}
