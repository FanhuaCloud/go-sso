package oidc

import (
	"strings"
	"time"
)

type ClaimsParams struct {
	Issuer      string
	Email       string
	Audience    string
	Nonce       string
	EmailSuffix string
	Now         time.Time
}

func Claims(params ClaimsParams) map[string]any {
	local := strings.TrimSuffix(params.Email, params.EmailSuffix)
	given := local
	family := "User"
	if parts := strings.FieldsFunc(local, func(r rune) bool { return r == '.' || r == '_' || r == '-' }); len(parts) > 1 {
		given = title(parts[0])
		family = title(parts[len(parts)-1])
	}

	claims := map[string]any{
		"iss":            params.Issuer,
		"sub":            StableSubject(params.Email),
		"aud":            params.Audience,
		"exp":            params.Now.Add(time.Hour).Unix(),
		"iat":            params.Now.Unix(),
		"auth_time":      params.Now.Unix(),
		"email":          params.Email,
		"email_verified": true,
		"given_name":     given,
		"family_name":    family,
	}
	if params.Nonce != "" {
		claims["nonce"] = params.Nonce
	}
	return claims
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
