package structs

import "net"

func SerializeIPList(ipList []net.IP) []string {
	result := make([]string, 0)
	for _, ip := range ipList {
		result = append(result, ip.String())
	}
	return result
}
