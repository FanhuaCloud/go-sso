package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func RandomToken(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func StableSubject(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(email)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
