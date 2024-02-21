package network

import (
	"Scanner/pkg/scanner/structs"
	"log"
)

type DNSSEC struct {
	Hostname  string
	QueryType uint16
	NoServer  bool
}

func singleMeasure(query DNSSEC) structs.DNSSECRecord {
	r := structs.DNSSECRecord{}
	rq, err := NewResolver()
	if err != nil {
		log.Fatalf("[ERROR] %v", err)
		r.Reason = err.Error()
		return r
	}
	_, chain, err := rq.StrictNSQuery(query.Hostname, query.QueryType, query.NoServer)
	if chain != nil {
		r.SignedZones = chain.ExportAuthChain()
	}
	if err != nil {
		if err == ErrInvalidQuery {
			r.Reason = err.Error()
			r.DNSSECExists = false
			r.DNSSECValid = false
		}
		if err == ErrResourceNotSigned {
			// Typical base case where there is no DNSSEC
			r.Reason = err.Error()
			r.DNSSECExists = false
			r.DNSSECValid = false
		}
		// All the following cases hint about DNSSEC but are invalid.
		if err == ErrInvalidRRsig || // Invalid RRSIG returned
			err == ErrRrsigValidationError || // Signature is invalid
			err == ErrRrsigValidityPeriod || // Signature has expired
			err == ErrDsInvalid || // Delegation is invalid
			err == ErrUnknownDsDigestType || // DigestType is unknown for DS
			err == ErrDnskeyNotAvailable || // DNSKEY was hinted but not available
			err == ErrDelegationChain { // Verify was called but with an empty delegation chain. Should not have happened.
			r.Reason = err.Error()
			r.DNSSECExists = true
			r.DNSSECValid = false

		}

		if err == ErrNoResult {
			r.Reason = err.Error()
		}
		return r
	} else {
		r.DNSSECExists = true
		r.DNSSECValid = true
		return r
	}
}

func (d DNSSEC) Query() structs.DNSSECRecord {
	return singleMeasure(d)
}
