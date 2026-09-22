/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fabricmsp "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/hyperledger/fabric-x-common/api/msppb"
	"google.golang.org/protobuf/proto"
)

type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

func TestSignerFromMSPCryptogenKey(t *testing.T) {
	_, keyPEM, certPEM := newTestECDSAIdentity(t)
	dir := writeTestMSP(t, "identity_sk", keyPEM, certPEM)

	signer, err := SignerFromMSP(dir, "Org1MSP")
	if err != nil {
		t.Fatalf("SignerFromMSP() error = %v", err)
	}

	serialized, err := signer.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error = %v", err)
	}

	var identity fabricmsp.SerializedIdentity
	if err := proto.Unmarshal(serialized, &identity); err != nil {
		t.Fatalf("unmarshal SerializedIdentity: %v", err)
	}
	if identity.Mspid != "Org1MSP" {
		t.Fatalf("Mspid = %q, want %q", identity.Mspid, "Org1MSP")
	}
	if !bytes.Equal(identity.IdBytes, certPEM) {
		t.Fatal("serialized identity does not contain the sign certificate")
	}
}

func TestSignerFromMSPFabricCAKey(t *testing.T) {
	_, keyPEM, certPEM := newTestECDSAIdentity(t)
	dir := writeTestMSP(t, "priv-key.pem", keyPEM, certPEM)

	if _, err := SignerFromMSP(dir, "Org1MSP"); err != nil {
		t.Fatalf("SignerFromMSP() with fabric-ca key name error = %v", err)
	}
}

func TestSignerSignProducesVerifiableLowSSignature(t *testing.T) {
	_, keyPEM, certPEM := newTestECDSAIdentity(t)
	dir := writeTestMSP(t, "identity_sk", keyPEM, certPEM)
	signer, err := SignerFromMSP(dir, "Org1MSP")
	if err != nil {
		t.Fatalf("SignerFromMSP() error = %v", err)
	}

	message := []byte("fabric-x identity signing test")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatal("failed to decode test certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key type = %T, want *ecdsa.PublicKey", cert.PublicKey)
	}

	var parsed ecdsaSignature
	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil {
		t.Fatalf("unmarshal ECDSA signature: %v", err)
	}
	if len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		t.Fatal("invalid DER ECDSA signature")
	}

	digest := sha256.Sum256(message)
	if !ecdsa.Verify(publicKey, digest[:], parsed.R, parsed.S) {
		t.Fatal("signature does not verify against the certificate public key")
	}

	halfOrder := new(big.Int).Rsh(new(big.Int).Set(publicKey.Params().N), 1)
	if parsed.S.Cmp(halfOrder) > 0 {
		t.Fatalf("signature S is not low-S: S=%s", parsed.S)
	}
}

func TestSignerSerializeWireCompatibleWithFabricXIdentity(t *testing.T) {
	_, keyPEM, certPEM := newTestECDSAIdentity(t)
	dir := writeTestMSP(t, "identity_sk", keyPEM, certPEM)
	signer, err := SignerFromMSP(dir, "Org1MSP")
	if err != nil {
		t.Fatalf("SignerFromMSP() error = %v", err)
	}

	serialized, err := signer.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error = %v", err)
	}

	var identity msppb.Identity
	if err := proto.Unmarshal(serialized, &identity); err != nil {
		t.Fatalf("unmarshal fabric-x identity: %v", err)
	}
	if identity.GetMspId() != "Org1MSP" {
		t.Fatalf("MspId = %q, want %q", identity.GetMspId(), "Org1MSP")
	}
	if !bytes.Equal(identity.GetCertificate(), certPEM) {
		t.Fatal("fabric-x identity does not contain the sign certificate")
	}
}

func TestSignerFromMSPErrors(t *testing.T) {
	_, validKeyPEM, certPEM := newTestECDSAIdentity(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal RSA PKCS#8 key: %v", err)
	}

	t.Run("missing directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "missing")
		assertSignerErrorContains(t, dir, "no private key found")
	})

	t.Run("empty keystore", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "keystore"), 0o700); err != nil {
			t.Fatalf("create keystore: %v", err)
		}
		assertSignerErrorContains(t, dir, "no private key found")
	})

	t.Run("missing signcerts", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, "keystore", "identity_sk"), validKeyPEM)
		assertSignerErrorContains(t, dir, "no signcert found")
	})

	t.Run("PKCS1 key", func(t *testing.T) {
		dir := writeTestMSP(t, "identity_sk", pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}), certPEM)
		assertSignerErrorContains(t, dir, "parse pkcs8 private key")
	})

	t.Run("PKCS8 RSA key", func(t *testing.T) {
		dir := writeTestMSP(t, "identity_sk", pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: rsaPKCS8,
		}), certPEM)
		assertSignerErrorContains(t, dir, "not an ECDSA private key")
	})
}

func newTestECDSAIdentity(t *testing.T) (*ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-user"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(4102444800, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return privateKey, keyPEM, certPEM
}

func writeTestMSP(t *testing.T, keyName string, keyPEM, certPEM []byte) string {
	t.Helper()

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "keystore", keyName), keyPEM)
	writeTestFile(t, filepath.Join(dir, "signcerts", "cert.pem"), certPEM)
	return dir
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertSignerErrorContains(t *testing.T, dir, want string) {
	t.Helper()

	_, err := SignerFromMSP(dir, "Org1MSP")
	if err == nil {
		t.Fatalf("SignerFromMSP() error = nil, want substring %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("SignerFromMSP() error = %q, want substring %q", err, want)
	}
}
