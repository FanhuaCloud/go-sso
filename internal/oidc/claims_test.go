package oidc

import (
	"testing"
	"time"
)

func TestClaimsDeriveProfileAndTokenFields(t *testing.T) {
	now := time.Unix(100, 0).UTC()

	claims := Claims(ClaimsParams{
		Issuer:      "https://issuer.example",
		Email:       "jane.doe@example.edu",
		Audience:    "chatgpt",
		Nonce:       "nonce-1",
		EmailSuffix: "@example.edu",
		Now:         now,
	})

	assertClaim(t, claims, "iss", "https://issuer.example")
	assertClaim(t, claims, "aud", "chatgpt")
	assertClaim(t, claims, "email", "jane.doe@example.edu")
	assertClaim(t, claims, "given_name", "Jane")
	assertClaim(t, claims, "family_name", "Doe")
	assertClaim(t, claims, "nonce", "nonce-1")
	assertClaim(t, claims, "sub", StableSubject("JANE.DOE@example.edu"))
	assertClaim(t, claims, "iat", int64(100))
	assertClaim(t, claims, "auth_time", int64(100))
	assertClaim(t, claims, "exp", int64(3700))
	if claims["email_verified"] != true {
		t.Fatalf("email_verified = %v", claims["email_verified"])
	}
}

func assertClaim(t *testing.T, claims map[string]any, key string, want any) {
	t.Helper()
	if got := claims[key]; got != want {
		t.Fatalf("%s = %#v, want %#v", key, got, want)
	}
}
