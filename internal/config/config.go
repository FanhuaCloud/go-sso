package config

import (
	"errors"
	"log"
	"os"
	"strings"
)

type Config struct {
	Addr           string
	Issuer         string
	ClientID       string
	ClientSecret   string
	RedirectURI    string
	PrivateKeyFile string
	HTTPSEnabled   bool
	HTTPSCertFile  string
	HTTPSKeyFile   string
	EmailSuffix    string
	GinMode        string
	TrustedProxies []string
	LoginAuthCode  string
	AllowAnyClient bool
}

func Load(dotenvPath string) Config {
	dotenv := LoadDotEnv(dotenvPath)
	cfg := Config{
		Addr:           configValue(dotenv, "ADDR", ":8080"),
		Issuer:         strings.TrimRight(configValue(dotenv, "OIDC_ISSUER", "http://localhost:8080"), "/"),
		ClientID:       configValue(dotenv, "OIDC_CLIENT_ID", "chatgpt"),
		ClientSecret:   configValue(dotenv, "OIDC_CLIENT_SECRET", "dev-secret-change-me"),
		RedirectURI:    configValue(dotenv, "OIDC_REDIRECT_URI", "https://external.auth.openai.com/sso/oidc/your-connection-id/callback"),
		PrivateKeyFile: configValue(dotenv, "OIDC_PRIVATE_KEY_FILE", ""),
		HTTPSCertFile:  configValue(dotenv, "HTTPS_CERT_FILE", ""),
		HTTPSKeyFile:   configValue(dotenv, "HTTPS_KEY_FILE", ""),
		EmailSuffix:    normalizeEmailSuffix(configValue(dotenv, "EMAIL_SUFFIX", "@example.edu")),
		GinMode:        normalizeGinMode(configValue(dotenv, "GIN_MODE", "release")),
		TrustedProxies: parseList(configValue(dotenv, "TRUSTED_PROXIES", "")),
		LoginAuthCode:  configValue(dotenv, "LOGIN_AUTH_CODE", ""),
	}
	cfg.AllowAnyClient = configValue(dotenv, "OIDC_ALLOW_ANY_CLIENT", "") == "1"
	cfg.HTTPSEnabled = configBool(dotenv, "HTTPS_ENABLED", false)
	return cfg
}

func Validate(cfg Config) error {
	if strings.TrimSpace(cfg.Addr) == "" {
		return errors.New("ADDR is required")
	}
	if strings.TrimSpace(cfg.Issuer) == "" {
		return errors.New("OIDC_ISSUER is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return errors.New("OIDC_CLIENT_ID is required")
	}
	if !cfg.AllowAnyClient && strings.TrimSpace(cfg.ClientSecret) == "" {
		return errors.New("OIDC_CLIENT_SECRET is required when OIDC_ALLOW_ANY_CLIENT=0")
	}
	if strings.TrimSpace(cfg.RedirectURI) == "" {
		return errors.New("OIDC_REDIRECT_URI is required")
	}
	if strings.TrimSpace(cfg.LoginAuthCode) == "" {
		return errors.New("LOGIN_AUTH_CODE is required")
	}
	if cfg.ClientSecret == "change-this-secret" {
		return errors.New("OIDC_CLIENT_SECRET must be changed from the example value")
	}
	if cfg.LoginAuthCode == "change-this-login-code" {
		return errors.New("LOGIN_AUTH_CODE must be changed from the example value")
	}
	return nil
}

func LoadDotEnv(path string) map[string]string {
	values := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		if path != "" && !errors.Is(err, os.ErrNotExist) {
			log.Printf("could not read %s: %v", path, err)
		}
		return values
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			log.Printf("ignoring invalid .env line: %s", line)
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		values[key] = unquoteDotEnvValue(value)
	}
	return values
}

func parseList(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

func normalizeGinMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "debug":
		return "debug"
	case "test":
		return "test"
	default:
		return "release"
	}
}

func normalizeEmailSuffix(suffix string) string {
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	if suffix == "" {
		return "@example.edu"
	}
	if !strings.HasPrefix(suffix, "@") {
		return "@" + suffix
	}
	return suffix
}

func unquoteDotEnvValue(value string) string {
	if len(value) < 2 {
		return value
	}
	if (strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`)) ||
		(strings.HasPrefix(value, `'`) && strings.HasSuffix(value, `'`)) {
		return value[1 : len(value)-1]
	}
	return value
}

func configValue(dotenv map[string]string, name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	if value := strings.TrimSpace(dotenv[name]); value != "" {
		return value
	}
	return fallback
}

func configBool(dotenv map[string]string, name string, fallback bool) bool {
	value := strings.ToLower(configValue(dotenv, name, ""))
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
