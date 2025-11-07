package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// HashFileSHA256 streams the file contents and returns the SHA-256 digest.
func HashFileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("hash file: %w", err)
	}
	sum := h.Sum(nil)
	return sum, nil
}

// SignDigest signs a SHA-256 digest with the provided private key.
func SignDigest(privateKey crypto.PrivateKey, digest []byte) ([]byte, error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest)
		if err != nil {
			return nil, fmt.Errorf("rsa sign: %w", err)
		}
		return sig, nil
	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, k, digest)
		if err != nil {
			return nil, fmt.Errorf("ecdsa sign: %w", err)
		}
		return sig, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", privateKey)
	}
}

// VerifyDigest verifies the signature against the digest with the given public key.
func VerifyDigest(publicKey crypto.PublicKey, digest, signature []byte) error {
	switch k := publicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, signature); err != nil {
			return fmt.Errorf("rsa verify: %w", err)
		}
		return nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, signature) {
			return errors.New("ecdsa signature invalid")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

// LoadPrivateKeyPEM parses a PEM encoded RSA or ECDSA private key.
func LoadPrivateKeyPEM(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA private key: %w", err)
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
		}
		switch k := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported PKCS8 private key type %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// LoadPublicKeyPEM parses a PEM encoded RSA or ECDSA public key.
func LoadPublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		switch k := key.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported public key type %T", key)
		}
	case "RSA PUBLIC KEY":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA public key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %s", block.Type)
	}
}

// EncodeSignatureBase64 returns the base64 representation of a signature.
func EncodeSignatureBase64(signature []byte) string {
	return base64.StdEncoding.EncodeToString(signature)
}

// DecodeSignatureBase64 decodes a base64 signature string.
func DecodeSignatureBase64(data string) ([]byte, error) {
	sig, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("decode base64 signature: %w", err)
	}
	return sig, nil
}
