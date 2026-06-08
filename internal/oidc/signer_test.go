package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignerCreatesVerifiableJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner(key)

	token, err := signer.SignJWT(map[string]any{"sub": "user-1", "aud": "chatgpt"})
	if err != nil {
		t.Fatalf("SignJWT returned error: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}

	var header map[string]any
	decodeJSONPart(t, parts[0], &header)
	if header["alg"] != "RS256" {
		t.Fatalf("alg = %v", header["alg"])
	}
	if header["kid"] != signer.KeyID() {
		t.Fatalf("kid = %v, want %s", header["kid"], signer.KeyID())
	}

	var claims map[string]any
	decodeJSONPart(t, parts[1], &claims)
	if claims["sub"] != "user-1" {
		t.Fatalf("sub = %v", claims["sub"])
	}

	unsigned := parts[0] + "." + parts[1]
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	jwk := signer.PublicJWK()
	if jwk["kid"] != signer.KeyID() {
		t.Fatalf("jwk kid = %v, want %s", jwk["kid"], signer.KeyID())
	}
	if jwk["e"] != "AQAB" {
		t.Fatalf("jwk exponent = %v", jwk["e"])
	}
}

func decodeJSONPart(t *testing.T, value string, out any) {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}
