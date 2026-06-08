package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestReadPrivateKeySupportsPKCS1AndPKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		block *pem.Block
	}{
		{
			name:  "pkcs1",
			block: &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)},
		},
		{
			name:  "pkcs8",
			block: mustPKCS8Block(t, key),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private.pem")
			if err := os.WriteFile(path, pem.EncodeToMemory(tt.block), 0o600); err != nil {
				t.Fatal(err)
			}

			got, err := ReadPrivateKey(path)
			if err != nil {
				t.Fatalf("ReadPrivateKey returned error: %v", err)
			}
			if got.N.Cmp(key.N) != 0 {
				t.Fatal("loaded key modulus does not match")
			}
		})
	}
}

func mustPKCS8Block(t *testing.T, key *rsa.PrivateKey) *pem.Block {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &pem.Block{Type: "PRIVATE KEY", Bytes: der}
}
