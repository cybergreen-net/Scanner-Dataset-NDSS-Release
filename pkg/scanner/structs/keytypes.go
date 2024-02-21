package structs

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
)

type PublicKeyType int

const (
	RSA PublicKeyType = iota
	DSA
	ECDSA
	Ed25519
	NotApplicableOrUnknown = 999
)

type KeyUsageType int

type ExtendedKeyUsageType int

var KeyEnumValues = []x509.KeyUsage{
	x509.KeyUsageDigitalSignature,
	x509.KeyUsageContentCommitment,
	x509.KeyUsageKeyEncipherment,
	x509.KeyUsageDataEncipherment,
	x509.KeyUsageKeyAgreement,
	x509.KeyUsageCertSign,
	x509.KeyUsageCRLSign,
	x509.KeyUsageEncipherOnly,
	x509.KeyUsageDecipherOnly}

var ExtendedKeyEnumValues = []x509.ExtKeyUsage{
	x509.ExtKeyUsageAny,
	x509.ExtKeyUsageServerAuth,
	x509.ExtKeyUsageClientAuth,
	x509.ExtKeyUsageCodeSigning,
	x509.ExtKeyUsageEmailProtection,
	x509.ExtKeyUsageIPSECEndSystem,
	x509.ExtKeyUsageIPSECTunnel,
	x509.ExtKeyUsageIPSECUser,
	x509.ExtKeyUsageTimeStamping,
	x509.ExtKeyUsageOCSPSigning,
	x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	x509.ExtKeyUsageNetscapeServerGatedCrypto,
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
	x509.ExtKeyUsageMicrosoftKernelCodeSigning}

func IdentifyPublicKeyType(pk any) (PublicKeyType, int) {
	switch key := pk.(type) {
	case *rsa.PublicKey:
		return RSA, key.Size() * 8
	case *dsa.PublicKey:
		return DSA, key.Y.BitLen()
	case *ecdsa.PublicKey:
		return ECDSA, key.Y.BitLen()
	case ed25519.PublicKey:
		return Ed25519, len(key)
	default:
		return NotApplicableOrUnknown, 0
	}
}

func SerializeKeyUsage(keyUsage x509.KeyUsage) []KeyUsageType {
	uses := make([]KeyUsageType, 0)
	for i, keyUsage509 := range KeyEnumValues {
		if keyUsage509&keyUsage != 0 {
			uses = append(uses, KeyUsageType(i))
		}
	}
	return uses
}

func SerializeExtendedKeyUsage(keyUsages []x509.ExtKeyUsage) []ExtendedKeyUsageType {
	// dict to remove duplicate uses
	uses := make(map[ExtendedKeyUsageType]int, 0)
	for _, singleKeyUsage := range keyUsages {
		for i, keyUsage509 := range ExtendedKeyEnumValues {
			if keyUsage509&singleKeyUsage != 0 {
				uses[ExtendedKeyUsageType(i)] = i
			}
		}
	}
	keys := make([]ExtendedKeyUsageType, len(uses))
	i := 0
	for key := range uses {
		keys[i] = key
		i++
	}
	return keys
}
