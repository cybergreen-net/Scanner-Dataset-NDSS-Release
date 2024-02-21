package localtls

import "crypto/tls"

// TLS13Ciphers Supported by TLS13
// Because of Go's limitation in configuration of TLS13 cipher suites
// the implementation is restricted to tls.TLS_AES_128_GCM_SHA256 (0x1301) [4865].
// The proposed alternative to use go:linkname is deprecated for newer versions of Go
// because of changes to Go to prevent private functions from being overwritten with linkname
// Detailed thread:
// 1. https://github.com/golang/go/issues/29349
// 2. https://www.joeshaw.org/abusing-go-linkname-to-customize-tls13-cipher-suites/
var TLS13Ciphers = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}
