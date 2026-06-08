package server

import (
	"crypto/rsa"
	"errors"
	"html/template"
	"log"
	"strings"
	"sync"
	"time"

	"go-sso/internal/config"
	"go-sso/internal/oidc"
	"go-sso/internal/version"

	"github.com/gin-gonic/gin"
)

const (
	authRequestTTL  = 10 * time.Minute
	cleanupInterval = time.Minute
)

type Server struct {
	cfg      config.Config
	signer   *oidc.Signer
	authMu   sync.Mutex
	authReqs map[string]authRequest
	codeMu   sync.Mutex
	codes    map[string]authCode
	tokenMu  sync.Mutex
	tokens   map[string]userToken
	tpl      *template.Template
	version  string
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

func New(cfg config.Config, key *rsa.PrivateKey, tpl *template.Template) *Server {
	return &Server{
		cfg:      cfg,
		signer:   oidc.NewSigner(key),
		authReqs: map[string]authRequest{},
		codes:    map[string]authCode{},
		tokens:   map[string]userToken{},
		tpl:      tpl,
		version:  version.Current(),
	}
}

func (s *Server) Router() (*gin.Engine, error) {
	r := gin.Default()
	if err := r.SetTrustedProxies(s.cfg.TrustedProxies); err != nil {
		return nil, err
	}
	r.GET("/", s.home)
	r.GET("/login", s.loginPage)
	r.POST("/login", s.login)
	r.GET("/authorize", s.authorize)
	r.POST("/token", s.token)
	r.GET("/userinfo", s.userinfo)
	r.GET("/jwks", s.jwks)
	r.GET("/.well-known/openid-configuration", s.discovery)
	r.GET("/healthz", func(c *gin.Context) { c.String(200, "ok") })
	return r, nil
}

func (s *Server) StartCleanup() {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			s.cleanupExpired(time.Now())
		}
	}()
}

func (s *Server) cleanupExpired(now time.Time) {
	s.authMu.Lock()
	for id, req := range s.authReqs {
		if now.Sub(req.CreatedAt) > authRequestTTL {
			delete(s.authReqs, id)
		}
	}
	s.authMu.Unlock()

	s.codeMu.Lock()
	for code, authCode := range s.codes {
		if now.After(authCode.ExpiresAt) {
			delete(s.codes, code)
		}
	}
	s.codeMu.Unlock()

	s.tokenMu.Lock()
	for token, userToken := range s.tokens {
		if now.After(userToken.ExpiresAt) {
			delete(s.tokens, token)
		}
	}
	s.tokenMu.Unlock()
}

func Run(r *gin.Engine, cfg config.Config) error {
	if !cfg.HTTPSEnabled {
		return r.Run(cfg.Addr)
	}
	if strings.TrimSpace(cfg.HTTPSCertFile) == "" || strings.TrimSpace(cfg.HTTPSKeyFile) == "" {
		return errors.New("HTTPS_ENABLED=1 requires HTTPS_CERT_FILE and HTTPS_KEY_FILE")
	}
	log.Printf("HTTPS enabled with cert %s", cfg.HTTPSCertFile)
	return r.RunTLS(cfg.Addr, cfg.HTTPSCertFile, cfg.HTTPSKeyFile)
}
