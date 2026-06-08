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
	gin.SetMode(gin.TestMode)

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := DefaultTemplates()
	if err != nil {
		t.Fatal(err)
	}
	s := New(config.Config{
		Addr:            ":0",
		Issuer:          "https://issuer.example",
		ClientID:        "chatgpt",
		ClientSecret:    "secret",
		RedirectURI:     "https://client.example/callback",
		EmailSuffix:     "@example.edu",
		GinMode:         gin.TestMode,
		LoginAuthCode:   "open-sesame",
		ChatGPTLoginURL: "https://chatgpt.com/auth/login?sso=true&connection=conn_test",
	}, key, tpl)
	router, err := s.Router()
	if err != nil {
		t.Fatal(err)
	}
	return router, key
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
