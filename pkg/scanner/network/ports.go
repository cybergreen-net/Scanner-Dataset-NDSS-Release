package network

import (
	"net"
	"strconv"
	"time"
)

var SMTPPorts = []int{
	25,   // mainly used for transmission of messages (not emails) between mail servers
	465,  // not recommended for secure connections
	587,  // TLS support
	2525, // TLS support
}

type PortScanReport struct {
	IP     net.IP
	Port   int
	isOpen bool
}

func selectivePortScan(ip net.IP, port int, taskReport chan PortScanReport) {
	targetInstance := net.JoinHostPort(ip.String(), strconv.FormatInt(int64(port), 10))
	_, err := net.DialTimeout("tcp", targetInstance, 5*time.Second)
	if err != nil {
		taskReport <- PortScanReport{
			IP:     ip,
			Port:   port,
			isOpen: false,
		}
		return
	}
	taskReport <- PortScanReport{
		IP:     ip,
		Port:   port,
		isOpen: true,
	}
	return
}

func PerformGreedyPortScan(ipAddresses []net.IP) []int {
	numTasks := len(ipAddresses) * len(SMTPPorts)
	tasks := make(chan PortScanReport, numTasks)

	for _, ip := range ipAddresses {
		for _, port := range SMTPPorts {
			go selectivePortScan(ip, port, tasks)
		}
	}

	openPortMap := make(map[int]bool, 0)
	for taskIndex := 0; taskIndex < numTasks; taskIndex++ {
		response := <-tasks
		if response.isOpen {
			openPortMap[response.Port] = true
		}
	}

	openPorts := make([]int, 0)
	for port := range openPortMap {
		openPorts = append(openPorts, port)
	}

	return openPorts
}
