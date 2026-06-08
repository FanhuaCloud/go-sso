package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"strings"
)

func LoadOrCreateKey(path string) (*rsa.PrivateKey, error) {
	path = strings.TrimSpace(path)
	if path != "" {
		if key, err := ReadPrivateKey(path); err == nil {
			return key, nil
		} else {
			log.Printf("could not read OIDC_PRIVATE_KEY_FILE: %v", err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func ReadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("missing PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rsaKey, nil
}

func KeyID(key *rsa.PrivateKey) string {
	sum := sha256.Sum256(key.PublicKey.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}
