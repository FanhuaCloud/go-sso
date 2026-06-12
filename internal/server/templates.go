package server

import (
	"bytes"
	"embed"
	"html/template"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

type homeView struct {
	ChatGPTLoginURL string
	Version         string
}

type loginView struct {
	RequestID       string
	Error           string
	EmailSuffixes   []string
	EmailSuffixText string
	Version         string
}

func DefaultTemplates() (*template.Template, error) {
	return template.ParseFS(templateFS, "templates/*.html")
}

func (s *Server) renderLogin(c statusWriter, status int, reqID, errMsg string) {
	s.renderHTML(c, status, "login.html", loginView{
		RequestID:       reqID,
		Error:           errMsg,
		EmailSuffixes:   s.cfg.EmailSuffixes,
		EmailSuffixText: strings.Join(s.cfg.EmailSuffixes, ", "),
		Version:         s.version,
	})
}

func (s *Server) renderHTML(c statusWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		c.String(500, "template render error")
		return
	}
	c.Data(status, "text/html; charset=utf-8", buf.Bytes())
}

type statusWriter interface {
	String(int, string, ...any)
	Data(int, string, []byte)
}
