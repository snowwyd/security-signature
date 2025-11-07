package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Algorithm identifiers.
const (
	AlgorithmRSA   = "rsa"
	AlgorithmECDSA = "ecdsa"
)

// GenerateKeyPair generates a key pair for the requested asymmetric algorithm.
// For RSA provide rsaBits (>0). For ECDSA supply curveName (p256, p384, p521).
func GenerateKeyPair(algorithm string, rsaBits int, curveName string) (privPEM, pubPEM []byte, err error) {
	switch algorithm {
	case AlgorithmRSA:
		if rsaBits <= 0 {
			rsaBits = 2048
		}
		return generateRSAKeyPair(rsaBits)
	case AlgorithmECDSA:
		if curveName == "" {
			curveName = "p256"
		}
		return generateECDSAKeyPair(curveName)
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func generateRSAKeyPair(bits int) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate RSA key: %w", err)
	}

	privDER := x509.MarshalPKCS1PrivateKey(priv)
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal RSA public key: %w", err)
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}

	return pem.EncodeToMemory(privBlock), pem.EncodeToMemory(pubBlock), nil
}

func generateECDSAKeyPair(curveName string) ([]byte, []byte, error) {
	curve := selectCurve(curveName)
	if curve == nil {
		return nil, nil, fmt.Errorf("unsupported ECDSA curve: %s", curveName)
	}

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal ECDSA private key: %w", err)
	}
	privBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal ECDSA public key: %w", err)
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}

	return pem.EncodeToMemory(privBlock), pem.EncodeToMemory(pubBlock), nil
}

func selectCurve(name string) elliptic.Curve {
	switch name {
	case "p256":
		return elliptic.P256()
	case "p384":
		return elliptic.P384()
	case "p521":
		return elliptic.P521()
	default:
		return nil
	}
}
