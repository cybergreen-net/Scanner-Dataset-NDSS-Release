package network

import (
	"Scanner/pkg/scanner/structs"
	"net"
	"regexp"
	"strings"
)

type SPF struct {
	Hostname string
}

type check struct {
	cnt int
}

var (
	mDirective = regexp.MustCompile("^(\\+|\\-|\\?|\\~)?(all|include|a|mx|ptr|ip4|ip6|exists):?(.*)$")
	mModifier  = regexp.MustCompile("^([a-z0-9\\-\\_\\.]+)=(.*)$")
)

type void struct{}

// CheckHost for SPF rules.
// ip - the IP address of the SMTP client that is emitting the mail, either IPv4 or IPv6.
// domain - the domain that provides the sought-after authorization information; initially, the domain portion of the "MAIL FROM" or "HELO" identity.
// sender - the "MAIL FROM" or "HELO" identity.
// helo - domain from helo, used as sender domain if sender is not specified.
func CheckHost(domain string) structs.CombinedSPFRecord {
	c := check{
		cnt: 0,
	}
	spfResult, allIPs, allErrors, depth := c.checkHost(domain, 0)

	errors := make([]structs.SPFError, 0, len(allErrors))
	for s := range allErrors {
		if s != "" {
			errors = append(errors, s)
		}
	}

	ips := make([]string, 0, len(allErrors))
	for s := range allIPs {
		ips = append(ips, s)
	}

	return structs.CombinedSPFRecord{SPFVersion: "spf1", SPFIPs: ips, Depth: depth, SPFResult: spfResult, SPFErrors: errors}
}

func (c *check) checkHost(domain string, depth int) (structs.SPFResult, map[string]void, map[structs.SPFError]void, int) {
	// updated by any recursive calls to checkHost
	maxDepth := depth

	allIPs := make(map[string]void, 0)
	allErrors := make(map[structs.SPFError]void)

	spfResult := structs.SPFResult{}
	spfResult.SimpleLookups = make([]structs.SimpleLookup, 0)
	spfResult.RecursiveLookups = make(map[string]structs.SPFResult)

	spf, r := LookupSPF(domain)

	spfResult.SPFText = spf
	// if SPF lookup failed
	if r.IsSet() {
		spfResult.SPFError = r
		allErrors[r] = void{}
		return spfResult, allIPs, allErrors, depth
	}

	terms := parseSPF(spf)

	for _, term := range terms {
		switch t := term.(type) {
		case directive:
			d := t
			var ips []string
			var netIPs []net.IP
			var spfError structs.SPFError
			var pointer string
			var param string
			var isLookup bool
			// 10 look-ups max, lookups: a, mx, include, exists, and redirect
			for _, lkup := range SPFLookupTags {
				if lkup == d.mechanism {
					c.cnt++
					isLookup = true
				}
			}
			// still store simple lookups if lookup cap is reached
			if c.cnt > 10 && isLookup {
				allErrors[structs.PermError_LookupCount] = void{}
				simpleLookup := structs.SimpleLookup{LookupType: d.mechanism, IPs: ips, EvaluationQuantifier: evalQualifier(d.qualifier), SPFError: structs.PermError_LookupCount, Pointer: pointer, Parameter: d.param}
				spfResult.SimpleLookups = append(spfResult.SimpleLookups, simpleLookup)
				continue
			} else {
				switch d.mechanism {
				case "a":
					dom := d.domain(domain)
					param = dom
					netIPs, spfError = c.check(dom, d.cidr())
					ips = netIPsToStrIPs(netIPs)
				case "mx":
					dom := d.domain(domain)
					param = dom
					// MX lookups count towards total lookup count, see rc section 4.6.4
					mxCount := 0
					netIPs, mxCount, spfError = c.checkMX(dom, d.cidr())
					c.cnt += max(0, mxCount-1) // add any additional mx lookups
					if c.cnt > 10 {
						spfError = structs.PermError_LookupCount
					}
					ips = netIPsToStrIPs(netIPs)
				case "include":
					dom := d.domain(domain)
					param = dom
					recursiveRes, foundIPs, foundErrors, localDepth := c.checkHost(dom, depth+1)
					maxDepth = max(localDepth, maxDepth)
					allIPs = appendStringSets(allIPs, foundIPs)
					allErrors = appendErrorSets(allErrors, foundErrors)
					recursiveRes.Type = "include"
					spfResult.RecursiveLookups[dom] = recursiveRes
				case "ptr":
					// deprecated
					ips = make([]string, 0)
					spfError = structs.PermError
					pointer = d.param
					param = d.param
				case "ip4":
					if !strings.Contains(d.param, "/") {
						d.param = d.param + "/32"
					}
					param = d.param
					ips = append(ips, d.param)

				case "ip6":
					if !strings.Contains(d.param, "/") {
						d.param = d.param + "/128"
					}
					ips = append(ips, d.param)

				case "all":
					spfResult.AllQualifier = evalQualifier(d.qualifier)

				case "exists":
					param = d.param
					ips = make([]string, 0)
				}

				if ips != nil || pointer != "" || spfError != "" {
					simpleLookup := structs.SimpleLookup{LookupType: d.mechanism, IPs: ips, EvaluationQuantifier: evalQualifier(d.qualifier), SPFError: spfError, Pointer: pointer, Parameter: param}
					spfResult.SimpleLookups = append(spfResult.SimpleLookups, simpleLookup)
					allErrors[spfError] = void{}
					allIPs = appendStringSetArray(allIPs, ips)
					spfResult.SimpleLookupIPs = append(spfResult.SimpleLookupIPs, ips...)
				}
				// if all parameter is reached, ignore anything after
				if spfResult.AllQualifier != "" {
					return spfResult, allIPs, allErrors, maxDepth
				}
			}

		case modifier:
			switch t.name {
			case "redirect":
				c.cnt++
				if c.cnt > 10 {
					allErrors[structs.PermError_LookupCount] = void{}
					spfResult.RecursiveLookups[t.value] = structs.SPFResult{SPFError: structs.PermError_LookupCount}
					return spfResult, allIPs, allErrors, maxDepth
				}
				recursiveRes, foundIPs, foundErrors, localDepth := c.checkHost(t.value, depth+1)
				maxDepth = max(localDepth, maxDepth)
				allIPs = appendStringSets(allIPs, foundIPs)
				allErrors = appendErrorSets(allErrors, foundErrors)
				recursiveRes.Type = "redirect"
				spfResult.RecursiveLookups[t.value] = recursiveRes
				return spfResult, allIPs, allErrors, maxDepth
			case "exp":
			default:
			}
			//	something to do with modifiers
		}
	}
	return spfResult, allIPs, allErrors, maxDepth
}

// given a domain, retrieve IPs and result
func (c *check) check(domain string, cidr string) ([]net.IP, structs.SPFError) {
	var ips []net.IP
	var err error

	ips, err = net.LookupIP(domain)

	if err != nil {
		return make([]net.IP, 0), structs.TempError
	}

	return ips, ""
}

// evalQualifier returns Pass if qualifier is + or "" or other spf results accordingly
func evalQualifier(q string) structs.EvaluationQuantifier {
	switch q {
	case "~":
		return structs.Softfail
	case "-":
		return structs.Fail
	case "?":
		return structs.Neutral
	default:
		return structs.Pass
	}
}

// Return IPs. If result is temp error, at least one MX is unresponsive
func (c *check) checkMX(domain string, cidr string) ([]net.IP, int, structs.SPFError) {
	ips, count, err := lookupMX(domain)
	if err != nil {
		return make([]net.IP, 0), count, structs.TempError
	}
	return ips, count, ""
}

type modifier struct {
	name  string
	value string
}

type directive struct {
	qualifier string
	mechanism string
	param     string
}

// domain returns default domain (param) or domain specified in spf record after : sign
func (d directive) domain(domain string) string {
	if d.param != "" {
		parts := strings.SplitN(d.param, "/", 2)
		return parts[0]
	}
	return domain
}

func (d directive) cidr() string {
	n := strings.Index(d.param, "/")
	if n != -1 {
		return d.param[n:]
	}
	return ""
}

// directive
// qualifier
// mechanism
// = *( 1*SP ( directive / modifier ) )
// = [ qualifier ] mechanism
// = "+" / "-" / "?" / "~"
// = ( all / include / a / mx / ptr / ip4 / ip6 / exists )

// ParseSPF record and return slice with directives and modifiers
func parseSPF(spf string) []interface{} {
	spf = strings.TrimSpace(strings.TrimPrefix(spf, "v=spf1"))

	var terms []interface{}
	parts := strings.Fields(spf)
	for _, t := range parts {
		dirMatch := mDirective.FindStringSubmatch(t)
		if len(dirMatch) > 0 {
			terms = append(terms, directive{
				qualifier: dirMatch[1],
				mechanism: dirMatch[2],
				param:     dirMatch[3],
			})
			continue
		} else {
			modMatch := mModifier.FindStringSubmatch(t)
			if len(modMatch) > 0 {
				terms = append(terms, modifier{
					name:  modMatch[1],
					value: modMatch[2],
				})
			}
		}
	}
	return terms
}

// adds suffix
func netIPsToStrIPs(netIPs []net.IP) []string {
	strIPs := make([]string, 0)
	for _, ip := range netIPs {
		if ip.To4() != nil {
			strIPs = append(strIPs, ip.String()+"/32")
		} else {
			strIPs = append(strIPs, ip.String()+"/128")
		}

	}
	return strIPs
}

func max(num1 int, num2 int) int {
	if num1 > num2 {
		return num1
	}
	return num2
}

//   v=spf1
//
//    550 5.7.1 SPF MAIL FROM check failed:
//    550 5.7.1 The domain example.com explains:
//    550 5.7.1 Please see http://www.example.com/mailpolicy.html

// Received-SPF:
// Authentication-Results:

func (s SPF) Query() structs.CombinedSPFRecord {
	return CheckHost(s.Hostname)
}

func appendErrorSets(m1 map[structs.SPFError]void, m2 map[structs.SPFError]void) map[structs.SPFError]void {
	m3 := make(map[structs.SPFError]void)
	for k, v := range m1 {
		m3[k] = v
	}
	for k, v := range m2 {
		m3[k] = v
	}
	return m3
}

func appendStringSets(m1 map[string]void, m2 map[string]void) map[string]void {
	m3 := make(map[string]void)
	for k, v := range m1 {
		m3[k] = v
	}
	for k, v := range m2 {
		m3[k] = v
	}
	return m3
}

func appendStringSetArray(m1 map[string]void, a1 []string) map[string]void {
	m3 := make(map[string]void)
	for k, v := range m1 {
		m3[k] = v
	}
	for _, v := range a1 {
		m3[v] = void{}
	}
	return m3
}
