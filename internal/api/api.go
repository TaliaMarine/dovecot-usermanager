// Package api serves the JSON API and the SPA.
package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/TaliaMarine/dovecot-usermanager/internal/auth"
	"github.com/TaliaMarine/dovecot-usermanager/internal/hash"
	"github.com/TaliaMarine/dovecot-usermanager/internal/passwd"
)

// Users is what the API needs from the kube layer.
type Users interface {
	Users(ctx context.Context) ([]string, error)
	Mutate(ctx context.Context, fn func(*passwd.File) error) error
	Restart(ctx context.Context) error
}

const (
	minPasswordLen = 10
	maxPasswordLen = 256
	generatedLen   = 24
	// CSRFHeader must be present on every mutating request; a cross-site form
	// or simple fetch cannot set it without a CORS preflight we never grant.
	CSRFHeader = "X-Requested-With"
	CSRFValue  = "dovecot-usermanager"
)

type Server struct {
	auth     *auth.Authenticator
	users    Users
	hasher   hash.Hasher
	origin   string // scheme://host of the redirect URL, for Origin checks
	frontend string
}

func New(a *auth.Authenticator, u Users, h hash.Hasher, redirectURL, frontendDir string) (*Server, error) {
	ru, err := url.Parse(redirectURL)
	if err != nil {
		return nil, err
	}
	return &Server{auth: a, users: u, hasher: h, origin: ru.Scheme + "://" + ru.Host, frontend: frontendDir}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /api/auth/login", s.auth.LoginHandler)
	mux.HandleFunc("GET /api/auth/callback", s.auth.CallbackHandler)
	mux.HandleFunc("POST /api/auth/logout", s.auth.LogoutHandler)
	mux.HandleFunc("GET /api/me", s.auth.Require(s.me))
	mux.HandleFunc("GET /api/users", s.auth.Require(s.listUsers))
	mux.HandleFunc("POST /api/users", s.auth.Require(s.createUser))
	mux.HandleFunc("PUT /api/users/{name}/password", s.auth.Require(s.setPassword))
	mux.HandleFunc("DELETE /api/users/{name}", s.auth.Require(s.deleteUser))
	mux.HandleFunc("POST /api/restart", s.auth.Require(s.restart))
	mux.HandleFunc("GET /", s.spa)
	return s.secure(mux)
}

// secure adds security headers and CSRF checks for unsafe methods.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if r.Header.Get(CSRFHeader) != CSRFValue {
				http.Error(w, "missing CSRF header", http.StatusForbidden)
				return
			}
			if o := r.Header.Get("Origin"); o != "" && o != s.origin {
				http.Error(w, "bad origin", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) spa(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	p := filepath.Join(s.frontend, filepath.Clean("/"+r.URL.Path))
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		p = filepath.Join(s.frontend, "index.html")
		w.Header().Set("Cache-Control", "no-store")
	}
	http.ServeFile(w, r, p)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) me(w http.ResponseWriter, _ *http.Request, sess auth.Session) {
	writeJSON(w, http.StatusOK, map[string]string{"name": sess.Name, "email": sess.Email, "scheme": s.hasher.Scheme()})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	users, err := s.users.Users(r.Context())
	if err != nil {
		slog.Error("list users", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not read the users secret")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

type passwordReq struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Generate bool   `json:"generate"`
}

// resolvePassword returns the clear text (generated or validated).
func resolvePassword(req passwordReq) (string, error) {
	if req.Generate {
		return GeneratePassword(generatedLen)
	}
	if len(req.Password) < minPasswordLen || len(req.Password) > maxPasswordLen {
		return "", errors.New("password must be 10-256 characters")
	}
	if strings.ContainsAny(req.Password, "\r\n\x00") {
		return "", errors.New("password contains invalid characters")
	}
	return req.Password, nil
}

// GeneratePassword returns a random alphanumeric password.
func GeneratePassword(n int) (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out), nil
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func (s *Server) mutateErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, passwd.ErrExists):
		writeErr(w, http.StatusConflict, "user already exists")
	case errors.Is(err, passwd.ErrNotFound):
		writeErr(w, http.StatusNotFound, "user not found")
	default:
		slog.Error("write users secret", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not update the users secret")
	}
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	var req passwordReq
	if !decode(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := passwd.ValidateUser(req.Name); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	pw, err := resolvePassword(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h, err := s.hasher.Hash(pw)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hashing failed")
		return
	}
	if err := s.users.Mutate(r.Context(), func(f *passwd.File) error { return f.Add(req.Name, h) }); err != nil {
		s.mutateErr(w, err)
		return
	}
	slog.Info("audit", "actor", sess.Actor(), "action", "user.create", "target", req.Name)
	resp := map[string]any{"name": req.Name}
	if req.Generate {
		resp["password"] = pw // shown once, never stored in clear text
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) setPassword(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	name := r.PathValue("name")
	var req passwordReq
	if !decode(w, r, &req) {
		return
	}
	pw, err := resolvePassword(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h, err := s.hasher.Hash(pw)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hashing failed")
		return
	}
	if err := s.users.Mutate(r.Context(), func(f *passwd.File) error { return f.SetHash(name, h) }); err != nil {
		s.mutateErr(w, err)
		return
	}
	slog.Info("audit", "actor", sess.Actor(), "action", "user.password", "target", name)
	resp := map[string]any{"name": name}
	if req.Generate {
		resp["password"] = pw
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	name := r.PathValue("name")
	if err := s.users.Mutate(r.Context(), func(f *passwd.File) error { return f.Delete(name) }); err != nil {
		s.mutateErr(w, err)
		return
	}
	slog.Info("audit", "actor", sess.Actor(), "action", "user.delete", "target", name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) restart(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if err := s.users.Restart(r.Context()); err != nil {
		slog.Error("restart dovecot", "error", err)
		writeErr(w, http.StatusInternalServerError, "could not restart Dovecot")
		return
	}
	slog.Info("audit", "actor", sess.Actor(), "action", "dovecot.restart")
	w.WriteHeader(http.StatusAccepted)
}
