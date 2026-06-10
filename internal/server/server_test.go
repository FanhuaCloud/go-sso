package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go-sso/internal/config"
	"go-sso/internal/version"

	"github.com/gin-gonic/gin"
)

func TestAuthorizationCodeFlow(t *testing.T) {
	router, key := newTestRouter(t)

	authorize := "/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"chatgpt"},
		"redirect_uri":  {"https://client.example/callback"},
		"scope":         {"openid email profile"},
		"state":         {"state-1"},
		"nonce":         {"nonce-1"},
	}.Encode()
	res := performRequest(router, http.MethodGet, authorize, nil, nil)
	if res.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, body = %s", res.Code, res.Body.String())
	}

	loginURL := res.Header().Get("Location")
	parsedLogin, err := url.Parse(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	requestID := parsedLogin.Query().Get("request")
	if requestID == "" {
		t.Fatal("authorize redirect did not include request id")
	}

	res = performRequest(router, http.MethodGet, loginURL, nil, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("login page status = %d", res.Code)
	}

	loginForm := url.Values{
		"request":   {requestID},
		"email":     {"Jane.Doe@EXAMPLE.EDU"},
		"auth_code": {"open-sesame"},
	}
	res = performForm(router, "/login", loginForm, "", "")
	if res.Code != http.StatusFound {
		t.Fatalf("login status = %d, body = %s", res.Code, res.Body.String())
	}

	callback, err := url.Parse(res.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Scheme != "https" || callback.Host != "client.example" || callback.Path != "/callback" {
		t.Fatalf("callback redirect = %s", callback.String())
	}
	if callback.Query().Get("state") != "state-1" {
		t.Fatalf("state = %q", callback.Query().Get("state"))
	}
	code := callback.Query().Get("code")
	if code == "" {
		t.Fatal("callback did not include code")
	}

	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://client.example/callback"},
	}
	res = performForm(router, "/token", tokenForm, "chatgpt", "secret")
	if res.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", res.Code, res.Body.String())
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&tokenResponse); err != nil {
		t.Fatal(err)
	}
	if tokenResponse.AccessToken == "" || tokenResponse.IDToken == "" {
		t.Fatalf("token response missing tokens: %+v", tokenResponse)
	}
	if tokenResponse.TokenType != "Bearer" || tokenResponse.ExpiresIn != 3600 {
		t.Fatalf("unexpected token response: %+v", tokenResponse)
	}

	claims := verifyJWT(t, key, tokenResponse.IDToken)
	if claims["iss"] != "https://issuer.example" {
		t.Fatalf("iss = %v", claims["iss"])
	}
	if claims["aud"] != "chatgpt" {
		t.Fatalf("aud = %v", claims["aud"])
	}
	if claims["email"] != "jane.doe@example.edu" {
		t.Fatalf("email = %v", claims["email"])
	}
	if claims["nonce"] != "nonce-1" {
		t.Fatalf("nonce = %v", claims["nonce"])
	}

	res = performRequest(router, http.MethodGet, "/userinfo", nil, map[string]string{
		"Authorization": "Bearer " + tokenResponse.AccessToken,
	})
	if res.Code != http.StatusOK {
		t.Fatalf("userinfo status = %d, body = %s", res.Code, res.Body.String())
	}
	var userinfo map[string]any
	if err := json.NewDecoder(res.Body).Decode(&userinfo); err != nil {
		t.Fatal(err)
	}
	if userinfo["email"] != "jane.doe@example.edu" {
		t.Fatalf("userinfo email = %v", userinfo["email"])
	}
	if _, ok := userinfo["iss"]; ok {
		t.Fatal("userinfo included issuer claim")
	}

	res = performForm(router, "/token", tokenForm, "chatgpt", "secret")
	if res.Code != http.StatusBadRequest {
		t.Fatalf("reused code status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestAuthorizeRejectsInvalidScopeWithOIDCRedirect(t *testing.T) {
	router, _ := newTestRouter(t)

	authorize := "/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"chatgpt"},
		"redirect_uri":  {"https://client.example/callback"},
		"scope":         {"email"},
		"state":         {"state-1"},
	}.Encode()
	res := performRequest(router, http.MethodGet, authorize, nil, nil)
	if res.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, body = %s", res.Code, res.Body.String())
	}
	redirect, err := url.Parse(res.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if redirect.Query().Get("error") != "invalid_scope" {
		t.Fatalf("error = %q", redirect.Query().Get("error"))
	}
	if redirect.Query().Get("state") != "state-1" {
		t.Fatalf("state = %q", redirect.Query().Get("state"))
	}
}

func TestDiscoveryAndJWKSExposeOIDCMetadata(t *testing.T) {
	router, _ := newTestRouter(t)

	res := performRequest(router, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("discovery status = %d, body = %s", res.Code, res.Body.String())
	}
	var discovery map[string]any
	if err := json.NewDecoder(res.Body).Decode(&discovery); err != nil {
		t.Fatal(err)
	}
	if discovery["issuer"] != "https://issuer.example" {
		t.Fatalf("issuer = %v", discovery["issuer"])
	}
	if discovery["authorization_endpoint"] != "https://issuer.example/authorize" {
		t.Fatalf("authorization_endpoint = %v", discovery["authorization_endpoint"])
	}
	if discovery["token_endpoint"] != "https://issuer.example/token" {
		t.Fatalf("token_endpoint = %v", discovery["token_endpoint"])
	}
	if discovery["jwks_uri"] != "https://issuer.example/jwks" {
		t.Fatalf("jwks_uri = %v", discovery["jwks_uri"])
	}

	res = performRequest(router, http.MethodGet, "/jwks", nil, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("jwks status = %d, body = %s", res.Code, res.Body.String())
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("jwks keys len = %d", len(jwks.Keys))
	}
	key := jwks.Keys[0]
	for _, field := range []string{"kty", "use", "kid", "alg", "n", "e"} {
		value, ok := key[field].(string)
		if !ok || value == "" {
			t.Fatalf("jwks key missing %s: %+v", field, key)
		}
	}
	if key["kty"] != "RSA" || key["alg"] != "RS256" {
		t.Fatalf("unexpected jwks key metadata: %+v", key)
	}
}

func TestLoginRejectsInvalidEmailSuffix(t *testing.T) {
	router, _ := newTestRouter(t)
	requestID := startLoginRequest(t, router)

	form := url.Values{
		"request":   {requestID},
		"email":     {"person@other.example"},
		"auth_code": {"open-sesame"},
	}
	res := performForm(router, "/login", form, "", "")
	if res.Code != http.StatusBadRequest {
		t.Fatalf("login status = %d, body = %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "Use an email ending in @example.edu.") {
		t.Fatalf("login body did not include suffix error: %s", res.Body.String())
	}
}

func TestLoginClearsAuthCodeFailuresAfterSuccess(t *testing.T) {
	router, _ := newTestRouter(t)
	requestID := startLoginRequest(t, router)

	form := url.Values{
		"request":   {requestID},
		"email":     {"person@example.edu"},
		"auth_code": {"wrong-code"},
	}
	res := performForm(router, "/login", form, "", "")
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("first failed login status = %d, body = %s", res.Code, res.Body.String())
	}

	form.Set("auth_code", "open-sesame")
	res = performForm(router, "/login", form, "", "")
	if res.Code != http.StatusFound {
		t.Fatalf("successful login status = %d, body = %s", res.Code, res.Body.String())
	}

	requestID = startLoginRequest(t, router)
	form.Set("request", requestID)
	form.Set("auth_code", "wrong-code")
	for i := 0; i < loginAuthCodeMaxFailures-1; i++ {
		res = performForm(router, "/login", form, "", "")
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("post-success failed login %d status = %d, body = %s", i+1, res.Code, res.Body.String())
		}
	}

	form.Set("auth_code", "open-sesame")
	res = performForm(router, "/login", form, "", "")
	if res.Code != http.StatusFound {
		t.Fatalf("post-success login status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestLoginRateLimitsInvalidAuthCodeByIP(t *testing.T) {
	router, _ := newTestRouter(t)
	requestID := startLoginRequest(t, router)

	form := url.Values{
		"request":   {requestID},
		"email":     {"person@example.edu"},
		"auth_code": {"wrong-code"},
	}
	for i := 0; i < loginAuthCodeMaxFailures; i++ {
		res := performForm(router, "/login", form, "", "")
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("login attempt %d status = %d, body = %s", i+1, res.Code, res.Body.String())
		}
	}

	form.Set("auth_code", "open-sesame")
	res := performForm(router, "/login", form, "", "")
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked login status = %d, body = %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "Too many invalid authorization code attempts.") {
		t.Fatalf("blocked login body did not include rate limit error: %s", res.Body.String())
	}
}

func TestTokenRejectsRedirectURIMismatch(t *testing.T) {
	router, _ := newTestRouter(t)
	code := completeLoginAndGetCode(t, router)

	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://client.example/other-callback"},
	}
	res := performForm(router, "/token", tokenForm, "chatgpt", "secret")
	if res.Code != http.StatusBadRequest {
		t.Fatalf("token status = %d, body = %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "invalid_grant") {
		t.Fatalf("token body did not include invalid_grant: %s", res.Body.String())
	}
}

func TestTokenRejectsInvalidClient(t *testing.T) {
	router, _ := newTestRouter(t)
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"does-not-matter"},
		"redirect_uri": {"https://client.example/callback"},
	}

	res := performForm(router, "/token", form, "chatgpt", "wrong-secret")
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("token status = %d, body = %s", res.Code, res.Body.String())
	}
	if res.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate header")
	}
}

func TestCleanupExpiredRemovesStaleState(t *testing.T) {
	s, _ := newTestServer(t)
	now := time.Unix(1_000, 0)

	s.authReqs["expired"] = authRequest{CreatedAt: now.Add(-authRequestTTL - time.Second)}
	s.authReqs["fresh"] = authRequest{CreatedAt: now}
	s.codes["expired"] = authCode{ExpiresAt: now.Add(-time.Second)}
	s.codes["fresh"] = authCode{ExpiresAt: now.Add(time.Second)}
	s.tokens["expired"] = userToken{ExpiresAt: now.Add(-time.Second)}
	s.tokens["fresh"] = userToken{ExpiresAt: now.Add(time.Second)}
	s.logins["expired"] = loginAttempt{
		FirstFailed:  now.Add(-loginAuthCodeFailureWindow - time.Second),
		BlockedUntil: now.Add(-time.Second),
	}
	s.logins["fresh"] = loginAttempt{
		FirstFailed: now,
	}

	s.cleanupExpired(now)

	if _, ok := s.authReqs["expired"]; ok {
		t.Fatal("expired auth request was not removed")
	}
	if _, ok := s.authReqs["fresh"]; !ok {
		t.Fatal("fresh auth request was removed")
	}
	if _, ok := s.codes["expired"]; ok {
		t.Fatal("expired auth code was not removed")
	}
	if _, ok := s.codes["fresh"]; !ok {
		t.Fatal("fresh auth code was removed")
	}
	if _, ok := s.tokens["expired"]; ok {
		t.Fatal("expired token was not removed")
	}
	if _, ok := s.tokens["fresh"]; !ok {
		t.Fatal("fresh token was removed")
	}
	if _, ok := s.logins["expired"]; ok {
		t.Fatal("expired login attempt was not removed")
	}
	if _, ok := s.logins["fresh"]; !ok {
		t.Fatal("fresh login attempt was removed")
	}
}

func TestRunRequiresTLSFilesWhenHTTPSEnabled(t *testing.T) {
	err := Run(gin.New(), config.Config{Addr: ":0", HTTPSEnabled: true})
	if err == nil || !strings.Contains(err.Error(), "HTTPS_ENABLED=1") {
		t.Fatalf("Run error = %v", err)
	}
}

func TestHomeRendersChatGPTLoginButton(t *testing.T) {
	router, _ := newTestRouter(t)

	res := performRequest(router, http.MethodGet, "/", nil, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("home status = %d, body = %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `href="https://chatgpt.com/auth/login?sso=true&amp;connection=conn_test"`) {
		t.Fatalf("home body did not include ChatGPT login link: %s", res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "登录 ChatGPT") {
		t.Fatalf("home body did not include button text: %s", res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "go-sso "+version.Current()) {
		t.Fatalf("home body did not include version: %s", res.Body.String())
	}
}

func TestLoginPageRendersVersion(t *testing.T) {
	router, _ := newTestRouter(t)
	requestID := startLoginRequest(t, router)

	res := performRequest(router, http.MethodGet, "/login?request="+url.QueryEscape(requestID), nil, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("login page status = %d, body = %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "go-sso "+version.Current()) {
		t.Fatalf("login body did not include version: %s", res.Body.String())
	}
}

func newTestRouter(t *testing.T) (*gin.Engine, *rsa.PrivateKey) {
	t.Helper()
	s, key := newTestServer(t)
	router, err := s.Router()
	if err != nil {
		t.Fatal(err)
	}
	return router, key
}

func newTestServer(t *testing.T) (*Server, *rsa.PrivateKey) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := DefaultTemplates()
	if err != nil {
		t.Fatal(err)
	}
	return New(config.Config{
		Addr:            ":0",
		Issuer:          "https://issuer.example",
		ClientID:        "chatgpt",
		ClientSecret:    "secret",
		RedirectURI:     "https://client.example/callback",
		EmailSuffix:     "@example.edu",
		GinMode:         gin.TestMode,
		LoginAuthCode:   "open-sesame",
		ChatGPTLoginURL: "https://chatgpt.com/auth/login?sso=true&connection=conn_test",
	}, key, tpl), key
}

func startLoginRequest(t *testing.T, router http.Handler) string {
	t.Helper()
	authorize := "/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"chatgpt"},
		"redirect_uri":  {"https://client.example/callback"},
		"scope":         {"openid"},
	}.Encode()
	res := performRequest(router, http.MethodGet, authorize, nil, nil)
	if res.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, body = %s", res.Code, res.Body.String())
	}
	loginURL, err := url.Parse(res.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	requestID := loginURL.Query().Get("request")
	if requestID == "" {
		t.Fatal("missing request id")
	}
	return requestID
}

func completeLoginAndGetCode(t *testing.T, router http.Handler) string {
	t.Helper()
	requestID := startLoginRequest(t, router)
	form := url.Values{
		"request":   {requestID},
		"email":     {"person@example.edu"},
		"auth_code": {"open-sesame"},
	}
	res := performForm(router, "/login", form, "", "")
	if res.Code != http.StatusFound {
		t.Fatalf("login status = %d, body = %s", res.Code, res.Body.String())
	}
	callback, err := url.Parse(res.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := callback.Query().Get("code")
	if code == "" {
		t.Fatal("callback did not include code")
	}
	return code
}

func performForm(router http.Handler, target string, form url.Values, username, password string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	return res
}

func performRequest(router http.Handler, method, target string, body *strings.Reader, headers map[string]string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body != nil {
		reader = body
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, reader)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	return res
}

func verifyJWT(t *testing.T, key *rsa.PrivateKey, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
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

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}
