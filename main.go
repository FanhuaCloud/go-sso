package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

//go:embed templates/*.html
var templateFS embed.FS

type config struct {
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

type server struct {
	cfg      config
	key      *rsa.PrivateKey
	keyID    string
	authMu   sync.Mutex
	authReqs map[string]authRequest
	codeMu   sync.Mutex
	codes    map[string]authCode
	tokenMu  sync.Mutex
	tokens   map[string]userToken
	tpl      *template.Template
}

type authRequest struct {
	ClientID    string
	RedirectURI string
	Scope       string
	State       string
	Nonce       string
	CreatedAt   time.Time
}

type authCode struct {
	ClientID    string
	RedirectURI string
	Scope       string
	Nonce       string
	Email       string
	ExpiresAt   time.Time
	Used        bool
}

type userToken struct {
	ClientID  string
	Email     string
	ExpiresAt time.Time
}

type homeView struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	EmailSuffix  string
}

type loginView struct {
	RequestID   string
	Error       string
	EmailSuffix string
}

func main() {
	cfg := loadConfig()
	gin.SetMode(cfg.GinMode)
	key := loadOrCreateKey(cfg.PrivateKeyFile)
	tpl := template.Must(template.ParseFS(templateFS, "templates/*.html"))

	s := &server{
		cfg:      cfg,
		key:      key,
		keyID:    keyID(key),
		authReqs: map[string]authRequest{},
		codes:    map[string]authCode{},
		tokens:   map[string]userToken{},
		tpl:      tpl,
	}

	r := gin.Default()
	if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		log.Fatalf("invalid TRUSTED_PROXIES: %v", err)
	}
	r.GET("/", s.home)
	r.GET("/login", s.loginPage)
	r.POST("/login", s.login)
	r.GET("/authorize", s.authorize)
	r.POST("/token", s.token)
	r.GET("/userinfo", s.userinfo)
	r.GET("/jwks", s.jwks)
	r.GET("/.well-known/openid-configuration", s.discovery)
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	log.Printf("OIDC server listening on %s", cfg.Addr)
	log.Printf("Discovery endpoint: %s/.well-known/openid-configuration", strings.TrimRight(cfg.Issuer, "/"))
	if err := runServer(r, cfg); err != nil {
		log.Fatal(err)
	}
}

func loadConfig() config {
	dotenv := loadDotEnv(".env")
	cfg := config{
		Addr:           configValue(dotenv, "ADDR", ":8080"),
		Issuer:         strings.TrimRight(configValue(dotenv, "OIDC_ISSUER", "http://localhost:8080"), "/"),
		ClientID:       configValue(dotenv, "OIDC_CLIENT_ID", "chatgpt"),
		ClientSecret:   configValue(dotenv, "OIDC_CLIENT_SECRET", "dev-secret-change-me"),
		RedirectURI:    configValue(dotenv, "OIDC_REDIRECT_URI", "https://external.auth.openai.com/sso/oidc/your-connection-id/callback"),
		PrivateKeyFile: configValue(dotenv, "OIDC_PRIVATE_KEY_FILE", ""),
		HTTPSCertFile:  configValue(dotenv, "HTTPS_CERT_FILE", ""),
		HTTPSKeyFile:   configValue(dotenv, "HTTPS_KEY_FILE", ""),
		EmailSuffix:    normalizeEmailSuffix(configValue(dotenv, "EMAIL_SUFFIX", "@example.edu")),
		GinMode:        normalizeGinMode(configValue(dotenv, "GIN_MODE", gin.ReleaseMode)),
		TrustedProxies: parseList(configValue(dotenv, "TRUSTED_PROXIES", "")),
		LoginAuthCode:  configValue(dotenv, "LOGIN_AUTH_CODE", ""),
	}
	cfg.AllowAnyClient = configValue(dotenv, "OIDC_ALLOW_ANY_CLIENT", "") == "1"
	cfg.HTTPSEnabled = configBool(dotenv, "HTTPS_ENABLED", false)
	return cfg
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
	case gin.DebugMode:
		return gin.DebugMode
	case gin.TestMode:
		return gin.TestMode
	default:
		return gin.ReleaseMode
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

func runServer(r *gin.Engine, cfg config) error {
	if !cfg.HTTPSEnabled {
		return r.Run(cfg.Addr)
	}
	if strings.TrimSpace(cfg.HTTPSCertFile) == "" || strings.TrimSpace(cfg.HTTPSKeyFile) == "" {
		return errors.New("HTTPS_ENABLED=1 requires HTTPS_CERT_FILE and HTTPS_KEY_FILE")
	}
	log.Printf("HTTPS enabled with cert %s", cfg.HTTPSCertFile)
	return r.RunTLS(cfg.Addr, cfg.HTTPSCertFile, cfg.HTTPSKeyFile)
}

func loadDotEnv(path string) map[string]string {
	values := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
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

func loadOrCreateKey(path string) *rsa.PrivateKey {
	path = strings.TrimSpace(path)
	if path != "" {
		if key, err := readPrivateKey(path); err == nil {
			return key
		} else {
			log.Printf("could not read OIDC_PRIVATE_KEY_FILE: %v", err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func readPrivateKey(path string) (*rsa.PrivateKey, error) {
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

func (s *server) discovery(c *gin.Context) {
	issuer := s.issuer(c)
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "given_name", "family_name"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	})
}

func (s *server) jwks(c *gin.Context) {
	pub := s.key.PublicKey
	c.JSON(http.StatusOK, gin.H{
		"keys": []gin.H{{
			"kty": "RSA",
			"use": "sig",
			"kid": s.keyID,
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func (s *server) authorize(c *gin.Context) {
	if c.Query("response_type") != "code" {
		oidcError(c, c.Query("redirect_uri"), c.Query("state"), "unsupported_response_type")
		return
	}
	if strings.TrimSpace(c.Query("client_id")) == "" {
		c.String(http.StatusBadRequest, "missing client_id")
		return
	}
	if !s.cfg.AllowAnyClient && c.Query("client_id") != s.cfg.ClientID {
		c.String(http.StatusBadRequest, "unknown client_id")
		return
	}
	if !s.validRedirectURI(c.Query("redirect_uri")) {
		c.String(http.StatusBadRequest, "invalid redirect_uri")
		return
	}
	if !strings.Contains(" "+c.Query("scope")+" ", " openid ") {
		oidcError(c, c.Query("redirect_uri"), c.Query("state"), "invalid_scope")
		return
	}

	reqID := randomToken(24)
	s.authMu.Lock()
	s.authReqs[reqID] = authRequest{
		ClientID:    c.Query("client_id"),
		RedirectURI: c.Query("redirect_uri"),
		Scope:       c.Query("scope"),
		State:       c.Query("state"),
		Nonce:       c.Query("nonce"),
		CreatedAt:   time.Now(),
	}
	s.authMu.Unlock()

	c.Redirect(http.StatusFound, "/login?request="+url.QueryEscape(reqID))
}

func (s *server) loginPage(c *gin.Context) {
	reqID := c.Query("request")
	s.authMu.Lock()
	_, ok := s.authReqs[reqID]
	s.authMu.Unlock()
	if !ok {
		s.renderLogin(c, http.StatusBadRequest, reqID, "Login request expired. Please start SSO again.")
		return
	}
	s.renderLogin(c, http.StatusOK, reqID, "")
}

func (s *server) login(c *gin.Context) {
	reqID := c.PostForm("request")
	email := strings.ToLower(strings.TrimSpace(c.PostForm("email")))
	loginAuthCode := strings.TrimSpace(c.PostForm("auth_code"))
	if !strings.HasSuffix(email, s.cfg.EmailSuffix) || strings.Count(email, "@") != 1 {
		s.renderLogin(c, http.StatusBadRequest, reqID, "Use an email ending in "+s.cfg.EmailSuffix+".")
		return
	}
	if s.cfg.LoginAuthCode == "" {
		s.renderLogin(c, http.StatusInternalServerError, reqID, "Login authorization code is not configured.")
		return
	}
	if loginAuthCode != s.cfg.LoginAuthCode {
		s.renderLogin(c, http.StatusUnauthorized, reqID, "Invalid authorization code.")
		return
	}

	s.authMu.Lock()
	req, ok := s.authReqs[reqID]
	if ok {
		delete(s.authReqs, reqID)
	}
	s.authMu.Unlock()
	if !ok {
		s.renderLogin(c, http.StatusBadRequest, reqID, "Login request expired. Please start SSO again.")
		return
	}

	code := randomToken(32)
	s.codeMu.Lock()
	s.codes[code] = authCode{
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		Scope:       req.Scope,
		Nonce:       req.Nonce,
		Email:       email,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
	s.codeMu.Unlock()

	redirect, _ := url.Parse(req.RedirectURI)
	q := redirect.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	redirect.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, redirect.String())
}

func (s *server) token(c *gin.Context) {
	if c.PostForm("grant_type") != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}

	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}
	if !s.validClient(clientID, clientSecret) {
		c.Header("WWW-Authenticate", `Basic realm="oidc"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	codeValue := c.PostForm("code")
	s.codeMu.Lock()
	code, ok := s.codes[codeValue]
	if ok {
		delete(s.codes, codeValue)
	}
	s.codeMu.Unlock()
	if !ok || code.Used || time.Now().After(code.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	if code.ClientID != clientID || code.RedirectURI != c.PostForm("redirect_uri") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	now := time.Now()
	claims := s.claims(c, code.Email, clientID, code.Nonce, now)
	idToken, err := s.signJWT(claims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	accessToken := randomToken(32)
	s.tokenMu.Lock()
	s.tokens[accessToken] = userToken{
		ClientID:  clientID,
		Email:     code.Email,
		ExpiresAt: now.Add(time.Hour),
	}
	s.tokenMu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (s *server) userinfo(c *gin.Context) {
	tokenValue := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	s.tokenMu.Lock()
	token, ok := s.tokens[tokenValue]
	s.tokenMu.Unlock()
	if !ok || time.Now().After(token.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	claims := s.claims(c, token.Email, token.ClientID, "", time.Now())
	delete(claims, "iss")
	delete(claims, "aud")
	delete(claims, "exp")
	delete(claims, "iat")
	delete(claims, "auth_time")
	c.JSON(http.StatusOK, claims)
}

func (s *server) home(c *gin.Context) {
	s.renderHTML(c, http.StatusOK, "home.html", homeView{
		Issuer:       s.issuer(c),
		ClientID:     s.cfg.ClientID,
		ClientSecret: s.cfg.ClientSecret,
		RedirectURI:  s.cfg.RedirectURI,
		EmailSuffix:  s.cfg.EmailSuffix,
	})
}

func (s *server) validClient(clientID, clientSecret string) bool {
	if s.cfg.AllowAnyClient {
		return clientID != ""
	}
	return clientID == s.cfg.ClientID && clientSecret == s.cfg.ClientSecret
}

func (s *server) validRedirectURI(raw string) bool {
	if s.cfg.RedirectURI == "" {
		return raw != ""
	}
	return raw == s.cfg.RedirectURI
}

func (s *server) claims(c *gin.Context, email, aud, nonce string, now time.Time) map[string]any {
	local := strings.TrimSuffix(email, s.cfg.EmailSuffix)
	given := local
	family := "User"
	if parts := strings.FieldsFunc(local, func(r rune) bool { return r == '.' || r == '_' || r == '-' }); len(parts) > 1 {
		given = title(parts[0])
		family = title(parts[len(parts)-1])
	}

	claims := map[string]any{
		"iss":            s.issuer(c),
		"sub":            stableSubject(email),
		"aud":            aud,
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"auth_time":      now.Unix(),
		"email":          email,
		"email_verified": true,
		"given_name":     given,
		"family_name":    family,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return claims
}

func (s *server) issuer(c *gin.Context) string {
	if s.cfg.Issuer != "" {
		return s.cfg.Issuer
	}
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host
}

func (s *server) signJWT(claims map[string]any) (string, error) {
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

func randomToken(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func keyID(key *rsa.PrivateKey) string {
	sum := sha256.Sum256(key.PublicKey.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func stableSubject(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(email)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func oidcError(c *gin.Context, redirectURI, state, code string) {
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": code})
		return
	}
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": code})
		return
	}
	q := redirect.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	redirect.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, redirect.String())
}

func (s *server) renderLogin(c *gin.Context, status int, reqID, errMsg string) {
	s.renderHTML(c, status, "login.html", loginView{
		RequestID:   reqID,
		Error:       errMsg,
		EmailSuffix: s.cfg.EmailSuffix,
	})
}

func (s *server) renderHTML(c *gin.Context, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		c.String(http.StatusInternalServerError, "template render error")
		return
	}
	c.Data(status, "text/html; charset=utf-8", buf.Bytes())
}
