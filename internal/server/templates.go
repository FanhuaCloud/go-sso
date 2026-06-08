package server

import (
	"bytes"
	"embed"
	"html/template"
)

//go:embed templates/*.html
var templateFS embed.FS

type homeView struct {
}

type loginView struct {
	RequestID   string
	Error       string
	EmailSuffix string
}

func DefaultTemplates() (*template.Template, error) {
	return template.ParseFS(templateFS, "templates/*.html")
}

func (s *Server) renderLogin(c statusWriter, status int, reqID, errMsg string) {
	s.renderHTML(c, status, "login.html", loginView{
		RequestID:   reqID,
		Error:       errMsg,
		EmailSuffix: s.cfg.EmailSuffix,
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
