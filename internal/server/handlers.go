package server

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"go-sso/internal/oidc"

	"github.com/gin-gonic/gin"
)

func (s *Server) discovery(c *gin.Context) {
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

func (s *Server) jwks(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"keys": []map[string]any{s.signer.PublicJWK()}})
}

func (s *Server) authorize(c *gin.Context) {
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

	reqID := oidc.RandomToken(24)
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

func (s *Server) loginPage(c *gin.Context) {
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

func (s *Server) login(c *gin.Context) {
	reqID := c.PostForm("request")
	email := postedEmail(c)
	loginAuthCode := strings.TrimSpace(c.PostForm("auth_code"))
	clientIP := c.ClientIP()
	if !s.validEmailSuffix(email) || strings.Count(email, "@") != 1 {
		s.renderLogin(c, http.StatusBadRequest, reqID, "Use an email ending in "+s.emailSuffixList()+".")
		return
	}
	if s.cfg.LoginAuthCode == "" {
		s.renderLogin(c, http.StatusInternalServerError, reqID, "Login authorization code is not configured.")
		return
	}
	if s.loginAuthCodeBlocked(clientIP, time.Now()) {
		s.renderLogin(c, http.StatusTooManyRequests, reqID, "Too many invalid authorization code attempts. Please try again later.")
		return
	}
	if loginAuthCode != s.cfg.LoginAuthCode {
		s.recordLoginAuthCodeFailure(clientIP, time.Now())
		s.renderLogin(c, http.StatusUnauthorized, reqID, "Invalid authorization code.")
		return
	}
	s.clearLoginAuthCodeFailures(clientIP)

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

	code := oidc.RandomToken(32)
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

func postedEmail(c *gin.Context) string {
	email := strings.ToLower(strings.TrimSpace(c.PostForm("email")))
	if email != "" {
		return email
	}
	local := strings.ToLower(strings.TrimSpace(c.PostForm("email_local")))
	suffix := strings.ToLower(strings.TrimSpace(c.PostForm("email_suffix")))
	return local + suffix
}

func (s *Server) token(c *gin.Context) {
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
	idToken, err := s.signer.SignJWT(claims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	accessToken := oidc.RandomToken(32)
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

func (s *Server) userinfo(c *gin.Context) {
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

func (s *Server) home(c *gin.Context) {
	s.renderHTML(c, http.StatusOK, "home.html", homeView{
		ChatGPTLoginURL: s.cfg.ChatGPTLoginURL,
		Version:         s.version,
	})
}

func (s *Server) validClient(clientID, clientSecret string) bool {
	if s.cfg.AllowAnyClient {
		return clientID != ""
	}
	return clientID == s.cfg.ClientID && clientSecret == s.cfg.ClientSecret
}

func (s *Server) validRedirectURI(raw string) bool {
	if s.cfg.RedirectURI == "" {
		return raw != ""
	}
	return raw == s.cfg.RedirectURI
}

func (s *Server) loginAuthCodeBlocked(ip string, now time.Time) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()

	attempt, ok := s.logins[ip]
	if !ok {
		return false
	}
	if now.Before(attempt.BlockedUntil) {
		return true
	}
	if now.Sub(attempt.FirstFailed) > loginAuthCodeFailureWindow {
		delete(s.logins, ip)
	}
	return false
}

func (s *Server) recordLoginAuthCodeFailure(ip string, now time.Time) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()

	attempt := s.logins[ip]
	if attempt.FirstFailed.IsZero() || now.Sub(attempt.FirstFailed) > loginAuthCodeFailureWindow {
		attempt = loginAttempt{FirstFailed: now}
	}
	attempt.Failures++
	if attempt.Failures >= loginAuthCodeMaxFailures {
		attempt.BlockedUntil = now.Add(loginAuthCodeBlockDuration)
	}
	s.logins[ip] = attempt
}

func (s *Server) clearLoginAuthCodeFailures(ip string) {
	s.loginMu.Lock()
	delete(s.logins, ip)
	s.loginMu.Unlock()
}

func (s *Server) claims(c *gin.Context, email, aud, nonce string, now time.Time) map[string]any {
	return oidc.Claims(oidc.ClaimsParams{
		Issuer:      s.issuer(c),
		Email:       email,
		Audience:    aud,
		Nonce:       nonce,
		EmailSuffix: emailSuffixForEmail(email, s.cfg.EmailSuffixes),
		Now:         now,
	})
}

func (s *Server) validEmailSuffix(email string) bool {
	return emailSuffixForEmail(email, s.cfg.EmailSuffixes) != ""
}

func (s *Server) emailSuffixList() string {
	return strings.Join(s.cfg.EmailSuffixes, ", ")
}

func emailSuffixForEmail(email string, suffixes []string) string {
	for _, suffix := range suffixes {
		if strings.HasSuffix(email, suffix) {
			return suffix
		}
	}
	return ""
}

func (s *Server) issuer(c *gin.Context) string {
	if s.cfg.Issuer != "" {
		return s.cfg.Issuer
	}
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host
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
