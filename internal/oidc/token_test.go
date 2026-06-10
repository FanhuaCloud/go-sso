package oidc

import (
	"regexp"
	"testing"
)

func TestRandomTokenReturnsURLSafeValue(t *testing.T) {
	token := RandomToken(32)
	if len(token) != 43 {
		t.Fatalf("token len = %d, want 43", len(token))
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(token) {
		t.Fatalf("token is not base64url-safe: %q", token)
	}
}

func TestStableSubjectNormalizesEmailCase(t *testing.T) {
	lower := StableSubject("person@example.edu")
	upper := StableSubject("PERSON@EXAMPLE.EDU")
	if lower == "" {
		t.Fatal("StableSubject returned empty subject")
	}
	if lower != upper {
		t.Fatalf("StableSubject differs by case: %q vs %q", lower, upper)
	}
}
