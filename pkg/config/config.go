package config

import (
	"net"
	"os"
	"strings"
)

const (
	Version = "0.0.1"
	// TLS
	DefaultTLSPort  = "443"
	DefaultResolver = "1.1.1.1:53"
	// SMTP
	SMTPHELO_Introduction = "cybergreen.net"
	// TLS & SMTP
	TLS_CIPHER_SUITE_SECOND_TIMEOUT = 15
	IP_SECOND_TIMEOUT               = 1 // A/AAAA record lookup timeout
	CIPHER_SUITE_WORKER_COUNT       = 5
	// SERVER
	SERVER_ADDRESS      = "0.0.0.0"
	SERVER_DEFAULT_PORT = "8080"
)

func GetServerHostnamePort() string {
	port := os.Getenv("PORT")
	if len(strings.TrimSpace(port)) == 0 {
		return net.JoinHostPort(SERVER_ADDRESS, SERVER_DEFAULT_PORT)
	} else {
		return net.JoinHostPort(SERVER_ADDRESS, port)
	}
}
