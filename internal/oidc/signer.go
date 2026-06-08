package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

type Signer struct {
	key   *rsa.PrivateKey
	keyID string
}

func NewSigner(key *rsa.PrivateKey) *Signer {
	return &Signer{
		key:   key,
		keyID: KeyID(key),
	}
}

func (s *Signer) KeyID() string {
	return s.keyID
}

func (s *Signer) PublicJWK() map[string]any {
	pub := s.key.PublicKey
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"kid": s.keyID,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func (s *Signer) SignJWT(claims map[string]any) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": s.keyID}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
