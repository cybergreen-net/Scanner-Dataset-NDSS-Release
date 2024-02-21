package network

import (
	"Scanner/pkg/config"
	"Scanner/pkg/scanner/structs"
	"net"
	"net/textproto"
	"strings"
	"time"
)

func GetSMTPBannerAndCapabilities(address string) structs.SMTPMetadata {
	response := structs.NewSMTPMetadata(address)

	dialer := &net.Dialer{
		Timeout: HOSTNAME_SECOND_TIMEOUT * time.Second,
	}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return response
	}
	conn.SetDeadline(time.Now().Add(time.Second * config.TLS_CIPHER_SUITE_SECOND_TIMEOUT))

	// C: TCP-CONNECTION-ACK
	// S: Banner Introduction.
	text := textproto.NewConn(conn)
	_, banner, err := text.ReadResponse(220)
	if err != nil {
		return response
	}
	response.Banner = banner

	// C: EHLO <introduction>
	// S: Capabilities ...
	format := "EHLO %s"
	ehloCode := 250

	id, err := text.Cmd(format, config.SMTPHELO_Introduction)
	if err != nil {
		return response
	}
	text.StartResponse(id)
	defer text.EndResponse(id)

	_, msg, err := text.ReadResponse(ehloCode)

	if err != nil {
		return response
	}

	capabilities := make(map[string]string)
	capabilitiesList := strings.Split(msg, "\n")
	if len(capabilitiesList) > 1 {
		capabilitiesList = capabilitiesList[1:]
		for _, line := range capabilitiesList {
			k, v, _ := strings.Cut(line, " ")
			capabilities[k] = v
		}
	}

	response.Capabilities = capabilities

	return response
}

func GetSMTPMetadata(requests <-chan string, results chan<- structs.SMTPMetadata) {
	for address := range requests {
		response := GetSMTPBannerAndCapabilities(address)
		results <- response
	}
}

func ParallelMailMetadataScan(addresses []string) map[string]structs.SMTPMetadata {
	result := make(map[string]structs.SMTPMetadata)
	numThreads := len(addresses)
	numTasks := len(addresses)

	tasks := make(chan string, numTasks)
	promises := make(chan structs.SMTPMetadata, numTasks)

	for workerIndex := 0; workerIndex < numThreads; workerIndex++ {
		go GetSMTPMetadata(tasks, promises)
	}

	for jobIndex := 0; jobIndex < numTasks; jobIndex++ {
		tasks <- addresses[jobIndex]
	}

	for resultIndex := 0; resultIndex < numTasks; resultIndex++ {
		res := <-promises
		result[res.GetHost()] = res
	}
	return result
}
