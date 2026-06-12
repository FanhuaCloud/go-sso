package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadReadsDotEnvAndPrefersEnvironment(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("OIDC_CLIENT_ID", "env-client")

	path := filepath.Join(t.TempDir(), ".env")
	data := strings.Join([]string{
		`ADDR=":9090"`,
		`OIDC_ISSUER=https://issuer.example/`,
		`OIDC_CLIENT_ID=file-client`,
		`OIDC_CLIENT_SECRET=file-secret`,
		`OIDC_REDIRECT_URI=https://client.example/callback`,
		`CHATGPT_SSO_CONNECTION_ID=conn_file`,
		`OIDC_PRIVATE_KEY_FILE=private.pem`,
		`HTTPS_CERT_FILE=cert.pem`,
		`HTTPS_KEY_FILE=key.pem`,
		`EMAIL_SUFFIX=Example.EDU, staff.example.edu`,
		`GIN_MODE=TEST`,
		`TRUSTED_PROXIES=127.0.0.1, ::1,`,
		`LOGIN_AUTH_CODE=open-sesame`,
		`OIDC_ALLOW_ANY_CLIENT=1`,
		`HTTPS_ENABLED=yes`,
	}, "\n")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := Load(path)

	if cfg.Addr != ":9090" {
		t.Fatalf("Addr = %q", cfg.Addr)
	}
	if cfg.Issuer != "https://issuer.example" {
		t.Fatalf("Issuer = %q", cfg.Issuer)
	}
	if cfg.ClientID != "env-client" {
		t.Fatalf("ClientID = %q", cfg.ClientID)
	}
	if got := strings.Join(cfg.EmailSuffixes, "|"); got != "@example.edu|@staff.example.edu" {
		t.Fatalf("EmailSuffixes = %q", got)
	}
	if cfg.GinMode != "test" {
		t.Fatalf("GinMode = %q", cfg.GinMode)
	}
	if !cfg.AllowAnyClient {
		t.Fatal("AllowAnyClient = false")
	}
	if !cfg.HTTPSEnabled {
		t.Fatal("HTTPSEnabled = false")
	}
	if got := strings.Join(cfg.TrustedProxies, "|"); got != "127.0.0.1|::1" {
		t.Fatalf("TrustedProxies = %q", got)
	}
	if cfg.ChatGPTLoginURL != "https://chatgpt.com/auth/login?connection=conn_file&sso=true" {
		t.Fatalf("ChatGPTLoginURL = %q", cfg.ChatGPTLoginURL)
	}
}

func TestLoadDerivesChatGPTLoginURLFromOpenAIRedirectURI(t *testing.T) {
	clearConfigEnv(t)

	path := filepath.Join(t.TempDir(), ".env")
	data := strings.Join([]string{
		`OIDC_REDIRECT_URI=https://external.auth.openai.com/sso/oidc/conn_123abc/callback`,
	}, "\n")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := Load(path)

	if cfg.ChatGPTLoginURL != "https://chatgpt.com/auth/login?connection=conn_123abc&sso=true" {
		t.Fatalf("ChatGPTLoginURL = %q", cfg.ChatGPTLoginURL)
	}
}

func TestLoadUsesExplicitChatGPTLoginURL(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("CHATGPT_SSO_LOGIN_URL", "https://chatgpt.com/auth/login?sso=true&connection=conn_override")

	cfg := Load("")

	if cfg.ChatGPTLoginURL != "https://chatgpt.com/auth/login?sso=true&connection=conn_override" {
		t.Fatalf("ChatGPTLoginURL = %q", cfg.ChatGPTLoginURL)
	}
}

func TestLoadUsesDefaultsWhenDotEnvIsMissing(t *testing.T) {
	clearConfigEnv(t)

	cfg := Load(filepath.Join(t.TempDir(), ".env"))

	if cfg.Addr != ":8080" {
		t.Fatalf("Addr = %q", cfg.Addr)
	}
	if cfg.Issuer != "http://localhost:8080" {
		t.Fatalf("Issuer = %q", cfg.Issuer)
	}
	if cfg.ClientID != "chatgpt" {
		t.Fatalf("ClientID = %q", cfg.ClientID)
	}
	if got := strings.Join(cfg.EmailSuffixes, "|"); got != "@example.edu" {
		t.Fatalf("EmailSuffixes = %q", got)
	}
	if cfg.HTTPSEnabled {
		t.Fatal("HTTPSEnabled = true")
	}
}

func TestValidateAcceptsCompleteConfig(t *testing.T) {
	cfg := validConfig()
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	cfg.ClientSecret = ""
	cfg.AllowAnyClient = true
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate with AllowAnyClient returned error: %v", err)
	}
}

func TestValidateRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{
			name: "missing addr",
			edit: func(cfg *Config) {
				cfg.Addr = " "
			},
			want: "ADDR is required",
		},
		{
			name: "missing client secret",
			edit: func(cfg *Config) {
				cfg.ClientSecret = ""
			},
			want: "OIDC_CLIENT_SECRET is required",
		},
		{
			name: "example client secret",
			edit: func(cfg *Config) {
				cfg.ClientSecret = "change-this-secret"
			},
			want: "must be changed",
		},
		{
			name: "example login code",
			edit: func(cfg *Config) {
				cfg.LoginAuthCode = "change-this-login-code"
			},
			want: "must be changed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.edit(&cfg)
			err := Validate(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate error = %v, want %q", err, tt.want)
			}
		})
	}
}

func validConfig() Config {
	return Config{
		Addr:          ":8080",
		Issuer:        "https://issuer.example",
		ClientID:      "chatgpt",
		ClientSecret:  "secret",
		RedirectURI:   "https://client.example/callback",
		EmailSuffixes: []string{"@example.edu"},
		GinMode:       "test",
		LoginAuthCode: "open-sesame",
	}
}

func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"ADDR",
		"OIDC_ISSUER",
		"OIDC_CLIENT_ID",
		"OIDC_CLIENT_SECRET",
		"OIDC_REDIRECT_URI",
		"CHATGPT_SSO_CONNECTION_ID",
		"CHATGPT_SSO_LOGIN_URL",
		"OIDC_PRIVATE_KEY_FILE",
		"HTTPS_CERT_FILE",
		"HTTPS_KEY_FILE",
		"EMAIL_SUFFIX",
		"GIN_MODE",
		"TRUSTED_PROXIES",
		"LOGIN_AUTH_CODE",
		"OIDC_ALLOW_ANY_CLIENT",
		"HTTPS_ENABLED",
	} {
		t.Setenv(name, "")
	}
}
