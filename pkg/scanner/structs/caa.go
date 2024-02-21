package structs

import "strings"

type CAARecord struct {
	IssueTag     map[Issuer]CAAResourceRecord `json:"issue"`
	IssueWildTag map[Issuer]CAAResourceRecord `json:"issuewild"`
	IODefTag     []string                     `json:"iodef"`
	Errors       []string                     `json:"errors"`
}

type CAAResourceRecord struct {
	Flag uint8      `json:"flag"`
	RR   []CAATagKV `json:"record"`
}

type CAATagKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Issuer string

// ParseCAAValue Use RFC 6844 as a reference for the tags and obtaining KV information
func ParseCAAValue(flag uint8, value string) (Issuer, CAAResourceRecord) {
	result := CAAResourceRecord{
		Flag: flag,
	}
	rrSet := make([]CAATagKV, 0)

	// First split by ;
	valueSegments := strings.Split(value, ";")

	if len(valueSegments) < 1 {
		return "", result
	}

	issuer := strings.TrimSpace(valueSegments[0])

	for index := 1; index < len(valueSegments); index++ {
		segmentString := strings.TrimSpace(valueSegments[index])
		// Obtain the KV Segments
		kvSegments := strings.Split(segmentString, "=")
		if len(kvSegments) == 2 {
			kv := CAATagKV{
				Key:   kvSegments[0],
				Value: kvSegments[1],
			}
			rrSet = append(rrSet, kv)
		}
	}

	result.RR = rrSet

	return Issuer(issuer), result
}
