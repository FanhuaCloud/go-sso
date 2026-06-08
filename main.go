package main

import (
	"log"
	"strings"

	"go-sso/internal/config"
	"go-sso/internal/oidc"
	"go-sso/internal/server"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load(".env")
	if err := config.Validate(cfg); err != nil {
		log.Fatal(err)
	}

	gin.SetMode(cfg.GinMode)

	key, err := oidc.LoadOrCreateKey(cfg.PrivateKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	tpl, err := server.DefaultTemplates()
	if err != nil {
		log.Fatal(err)
	}

	s := server.New(cfg, key, tpl)
	s.StartCleanup()

	r, err := s.Router()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("OIDC server listening on %s", cfg.Addr)
	log.Printf("Discovery endpoint: %s/.well-known/openid-configuration", strings.TrimRight(cfg.Issuer, "/"))
	if err := server.Run(r, cfg); err != nil {
		log.Fatal(err)
	}
}
