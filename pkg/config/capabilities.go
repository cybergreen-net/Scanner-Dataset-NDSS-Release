package config

type Capabilities struct {
	Capabilities []string `json:"capabilities"`
}

func IdentifyCapabilities() Capabilities {
	return Capabilities{
		Capabilities: []string{"dns-cache", "filter-policy"},
	}
}
