package structs

import (
	"github.com/emersion/go-msgauth/dmarc"
	"time"
)

type DMARCRecord struct {
	DKIMAlignment      dmarc.AlignmentMode  `json:"dkimAlignment"`
	SPFAlignment       dmarc.AlignmentMode  `json:"spfAlignment"`
	FailureOptions     string               `json:"failureOptions"`
	Policy             dmarc.Policy         `json:"policy"`
	Percent            *int                 `json:"percent"`
	ReportFormat       []dmarc.ReportFormat `json:"reportFormat"`
	ReportInterval     time.Duration        `json:"reportInterval"`
	ReportURIAggregate []string             `json:"reportURIAggregate"`
	ReportURIFailure   []string             `json:"reportURIFailure"`
	SubdomainPolicy    dmarc.Policy         `json:"subdomainPolicy"`
}
