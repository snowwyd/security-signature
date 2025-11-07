package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/qyteboii/security-signature/pkg/signature"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "keygen":
		if err := runKeygen(os.Args[2:]); err != nil {
			exitWithError(err)
		}
	case "sign":
		if err := runSign(os.Args[2:]); err != nil {
			exitWithError(err)
		}
	case "verify":
		if err := runVerify(os.Args[2:]); err != nil {
			exitWithError(err)
		}
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage(os.Stderr)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `Usage: security-signature <command> [options]

Commands:
  keygen   Generate a new key pair (RSA or ECDSA)
  sign     Sign a file with a private key
  verify   Verify a file signature with a public key

Run "security-signature <command> -h" for command-specific options.
`)
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	algo := fs.String("algo", signature.AlgorithmRSA, "algorithm to use: rsa or ecdsa")
	rsaBits := fs.Int("bits", 2048, "RSA key size in bits")
	curve := fs.String("curve", "p256", "ECDSA curve: p256, p384, p521")
	privPath := fs.String("out-priv", "private_key.pem", "path to write the private key")
	pubPath := fs.String("out-pub", "public_key.pem", "path to write the public key")
	fs.Parse(args)

	privPEM, pubPEM, err := signature.GenerateKeyPair(*algo, *rsaBits, *curve)
	if err != nil {
		return err
	}

	if err := os.WriteFile(*privPath, privPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(*pubPath, pubPEM, 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	fmt.Printf("Keys generated:\n  Private: %s\n  Public:  %s\n", *privPath, *pubPath)
	return nil
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "private_key.pem", "path to PEM encoded private key")
	inPath := fs.String("in", "", "path to the file to sign")
	sigPath := fs.String("out", "signature.sig", "path to write the base64 signature")
	fs.Parse(args)

	if *inPath == "" {
		return errors.New("input file is required (use -in)")
	}

	privData, err := os.ReadFile(*keyPath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	privKey, err := signature.LoadPrivateKeyPEM(privData)
	if err != nil {
		return err
	}

	digest, err := signature.HashFileSHA256(*inPath)
	if err != nil {
		return err
	}

	sigBytes, err := signature.SignDigest(privKey, digest)
	if err != nil {
		return err
	}

	sigBase64 := signature.EncodeSignatureBase64(sigBytes)
	if err := os.WriteFile(*sigPath, []byte(sigBase64), 0644); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}

	fmt.Printf("Signature written to %s\n", *sigPath)
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	keyPath := fs.String("key", "public_key.pem", "path to PEM encoded public key")
	inPath := fs.String("in", "", "path to the signed file")
	sigPath := fs.String("sig", "signature.sig", "path to the base64 signature file")
	fs.Parse(args)

	if *inPath == "" {
		return errors.New("input file is required (use -in)")
	}

	pubData, err := os.ReadFile(*keyPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	pubKey, err := signature.LoadPublicKeyPEM(pubData)
	if err != nil {
		return err
	}

	digest, err := signature.HashFileSHA256(*inPath)
	if err != nil {
		return err
	}

	sigData, err := os.ReadFile(*sigPath)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	sigBytes, err := signature.DecodeSignatureBase64(string(sigData))
	if err != nil {
		return err
	}

	if err := signature.VerifyDigest(pubKey, digest, sigBytes); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	fmt.Println("Signature is valid")
	return nil
}

func exitWithError(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}
