package structs

type Request struct {
	Hostname string `json:"hostname"`
	NoServer bool   `json:"noServer"`
}

type DNSRequest struct {
	Hostname  string `json:"hostname"`
	QueryType uint16
	NoServer  bool `json:"noServer"`
}

type StatusRecord struct {
	Err   string `json:"error"`
	Valid bool   `json:"isValid"`
}
