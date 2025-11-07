package tests

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qyteboii/security-signature/pkg/signature"
)

func TestGenerateKeyPairRSA(t *testing.T) {
	privPEM, pubPEM, err := signature.GenerateKeyPair(signature.AlgorithmRSA, 2048, "")
	if err != nil {
		t.Fatalf("GenerateKeyPair RSA failed: %v", err)
	}
	if len(privPEM) == 0 || len(pubPEM) == 0 {
		t.Fatalf("expected non-empty PEM output")
	}

	block, _ := pem.Decode(privPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("unexpected private key block type: %v", block)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse RSA private key: %v", err)
	}
	if key.N.BitLen() != 2048 {
		t.Fatalf("expected 2048 bit key, got %d", key.N.BitLen())
	}

	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil {
		t.Fatalf("failed to decode public key")
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if _, ok := pubAny.(*rsa.PublicKey); !ok {
		t.Fatalf("expected *rsa.PublicKey got %T", pubAny)
	}
}

func TestGenerateKeyPairECDSA(t *testing.T) {
	privPEM, pubPEM, err := signature.GenerateKeyPair(signature.AlgorithmECDSA, 0, "p256")
	if err != nil {
		t.Fatalf("GenerateKeyPair ECDSA failed: %v", err)
	}

	block, _ := pem.Decode(privPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatalf("unexpected private key block type: %v", block)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse EC private key: %v", err)
	}
	if key.Curve.Params().Name != "P-256" {
		t.Fatalf("unexpected curve: %s", key.Curve.Params().Name)
	}

	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil {
		t.Fatalf("failed to decode public key")
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if _, ok := pubAny.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey got %T", pubAny)
	}
}

func TestHashFileSHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	content := []byte("hello world")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	digest, err := signature.HashFileSHA256(path)
	if err != nil {
		t.Fatalf("HashFileSHA256: %v", err)
	}
	want := sha256.Sum256(content)
	if !bytes.Equal(digest, want[:]) {
		t.Fatalf("unexpected digest")
	}
}

func TestSignAndVerifyRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	digest := sha256.Sum256([]byte("data"))
	sig, err := signature.SignDigest(priv, digest[:])
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	if err := signature.VerifyDigest(&priv.PublicKey, digest[:], append([]byte(nil), sig...)); err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}

	sig[0] ^= 0xFF
	if err := signature.VerifyDigest(&priv.PublicKey, digest[:], sig); err == nil {
		t.Fatalf("expected verify error for tampered signature")
	}
}

func TestLoadKeysFromPEM(t *testing.T) {
	privPEM, pubPEM, err := signature.GenerateKeyPair(signature.AlgorithmRSA, 2048, "")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	privKey, err := signature.LoadPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM: %v", err)
	}
	if _, ok := privKey.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected *rsa.PrivateKey got %T", privKey)
	}

	pubKey, err := signature.LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM: %v", err)
	}
	if _, ok := pubKey.(*rsa.PublicKey); !ok {
		t.Fatalf("expected *rsa.PublicKey got %T", pubKey)
	}
}

func TestEncodeDecodeSignatureBase64(t *testing.T) {
	data := []byte{0, 1, 2, 3, 4}
	encoded := signature.EncodeSignatureBase64(data)
	decoded, err := signature.DecodeSignatureBase64(encoded)
	if err != nil {
		t.Fatalf("DecodeSignatureBase64: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("decoded data mismatch")
	}
}

func TestSignDigestUnsupportedKey(t *testing.T) {
	digest := sha256.Sum256([]byte("data"))
	if _, err := signature.SignDigest(struct{}{}, digest[:]); err == nil {
		t.Fatalf("expected error for unsupported key type")
	}
}

func TestVerifyDigestUnsupportedKey(t *testing.T) {
	digest := sha256.Sum256([]byte("data"))
	if err := signature.VerifyDigest(struct{}{}, digest[:], []byte("sig")); err == nil {
		t.Fatalf("expected error for unsupported key type")
	}
}

func TestHashFileSHA256MissingFile(t *testing.T) {
	if _, err := signature.HashFileSHA256("nonexistent"); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestCLIFlowRSA(t *testing.T) {
	bin := buildBinary(t)

	dir := t.TempDir()
	privPath := filepath.Join(dir, "rsa_priv.pem")
	pubPath := filepath.Join(dir, "rsa_pub.pem")

	runCommand(t, dir, bin, "keygen", "-algo", "rsa", "-bits", "2048", "-out-priv", privPath, "-out-pub", pubPath)

	dataPath := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(dataPath, []byte("important data"), 0600); err != nil {
		t.Fatalf("write data: %v", err)
	}

	sigPath := filepath.Join(dir, "data.sig")
	runCommand(t, dir, bin, "sign", "-key", privPath, "-in", dataPath, "-out", sigPath)

	runCommand(t, dir, bin, "verify", "-key", pubPath, "-in", dataPath, "-sig", sigPath)

	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	if strings.TrimSpace(string(sigData)) == "" {
		t.Fatalf("signature output is empty")
	}
}

func TestCLISignRequiresInput(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	cmdErr := runCommandExpectError(t, dir, bin, "sign", "-key", "nonexistent")
	if !strings.Contains(cmdErr, "input file is required") {
		t.Fatalf("unexpected error: %s", cmdErr)
	}
}

func TestCLIVerifyRequiresInput(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	cmdErr := runCommandExpectError(t, dir, bin, "verify", "-key", "nonexistent")
	if !strings.Contains(cmdErr, "input file is required") {
		t.Fatalf("unexpected error: %s", cmdErr)
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	name := "security-signature"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binPath := filepath.Join(dir, name)

	cmd := exec.Command("go", "build", "-o", binPath, "./cmd")
	cmd.Dir = projectRoot(t)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, stderr.String())
	}
	return binPath
}

func runCommand(t *testing.T, dir, bin string, args ...string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if out, err := cmd.Output(); err != nil {
		t.Fatalf("command failed: %v\n%s", err, stderr.String())
	} else if testing.Verbose() {
		t.Logf("%s", out)
	}
}

func runCommandExpectError(t *testing.T, dir, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected command to fail")
	}
	return stderr.String()
}

func projectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatalf("go.mod not found from %s", dir)
		}
		dir = next
	}
}
