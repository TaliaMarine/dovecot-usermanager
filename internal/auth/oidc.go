package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	stateCookie    = "um_oidc_state"
	verifierCookie = "um_oidc_verifier"
	returnCookie   = "um_oidc_return"
	flowTTL        = 10 * time.Minute
)

// Authenticator drives Authorization Code + PKCE (S256) as a public client:
// there is no client secret anywhere.
type Authenticator struct {
	cfg        oauth2.Config
	verifier   *oidc.IDTokenVerifier
	sessions   *SessionManager
	adminGroup string
	secure     bool
}

// NewAuthenticator discovers the provider. adminGroup must appear in the
// ID token's "groups" claim for a login to be accepted.
func NewAuthenticator(ctx context.Context, issuerURL, clientID, redirectURL, adminGroup string, sessions *SessionManager) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams // public client: client_id in the body
	u, err := url.Parse(redirectURL)
	if err != nil {
		return nil, fmt.Errorf("parse redirect URL: %w", err)
	}
	return &Authenticator{
		cfg: oauth2.Config{
			ClientID: clientID, RedirectURL: redirectURL, Endpoint: endpoint,
			Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier:   provider.Verifier(&oidc.Config{ClientID: clientID}),
		sessions:   sessions,
		adminGroup: adminGroup,
		secure:     u.Scheme == "https",
	}, nil
}

// HasGroup reports whether group is in groups.
func HasGroup(groups []string, group string) bool { return slices.Contains(groups, group) }

// SafeReturn only allows same-site absolute paths, defeating open redirects.
func SafeReturn(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || strings.ContainsAny(p, "\r\n") {
		return "/"
	}
	if strings.HasPrefix(p, "/api/") {
		return "/"
	}
	return p
}

func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *Authenticator) setFlow(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/api/auth", HttpOnly: true, Secure: a.secure,
		SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(flowTTL),
	})
}

func (a *Authenticator) clearFlow(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/api/auth", MaxAge: -1})
}

// LoginHandler redirects to the provider. ?return=/path is restored after login.
func (a *Authenticator) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randToken()
	if err != nil {
		http.Error(w, "failed to start login", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	a.setFlow(w, stateCookie, state)
	a.setFlow(w, verifierCookie, verifier)
	a.setFlow(w, returnCookie, base64.RawURLEncoding.EncodeToString([]byte(SafeReturn(r.URL.Query().Get("return")))))
	http.Redirect(w, r, a.cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (a *Authenticator) fail(w http.ResponseWriter, r *http.Request, reason string, err error) {
	if err != nil {
		slog.Warn("login failed", "reason", reason, "error", err)
	} else {
		slog.Warn("login failed", "reason", reason)
	}
	http.Redirect(w, r, "/?auth_error="+url.QueryEscape(reason), http.StatusFound)
}

// CallbackHandler completes the flow. Failures redirect to the SPA with
// ?auth_error=<reason> so it can show an error instead of looping.
func (a *Authenticator) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		a.fail(w, r, "provider_error", fmt.Errorf("%s: %s", e, q.Get("error_description")))
		return
	}
	sc, err := r.Cookie(stateCookie)
	if err != nil || sc.Value == "" || sc.Value != q.Get("state") {
		a.fail(w, r, "invalid_state", err)
		return
	}
	vc, err := r.Cookie(verifierCookie)
	if err != nil {
		a.fail(w, r, "invalid_flow", err)
		return
	}
	returnTo := "/"
	if rc, err := r.Cookie(returnCookie); err == nil {
		if b, err := base64.RawURLEncoding.DecodeString(rc.Value); err == nil {
			returnTo = SafeReturn(string(b))
		}
	}
	for _, n := range []string{stateCookie, verifierCookie, returnCookie} {
		a.clearFlow(w, n)
	}

	token, err := a.cfg.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(vc.Value))
	if err != nil {
		a.fail(w, r, "token_exchange", err)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		a.fail(w, r, "no_id_token", nil)
		return
	}
	idToken, err := a.verifier.Verify(r.Context(), raw)
	if err != nil {
		a.fail(w, r, "id_token_invalid", err)
		return
	}
	var claims struct {
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		a.fail(w, r, "claims_invalid", err)
		return
	}
	who := claims.Email
	if who == "" {
		who = claims.PreferredUsername
	}
	if !HasGroup(claims.Groups, a.adminGroup) {
		slog.Warn("login denied: missing group", "user", who, "group", a.adminGroup)
		a.fail(w, r, "forbidden", nil)
		return
	}
	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}
	if err := a.sessions.Issue(w, idToken.Subject, who, name); err != nil {
		a.fail(w, r, "session", err)
		return
	}
	slog.Info("audit", "actor", who, "action", "login")
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// LogoutHandler clears the session.
func (a *Authenticator) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	a.sessions.Clear(w)
	w.WriteHeader(http.StatusNoContent)
}

// Require wraps h: 401 JSON-less status without a valid session.
func (a *Authenticator) Require(h func(http.ResponseWriter, *http.Request, Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.sessions.FromRequest(r)
		if !ok {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		h(w, r, s)
	}
}

// NewTestAuthenticator builds an Authenticator without OIDC discovery, for
// tests of code that only needs session handling (Require).
func NewTestAuthenticator(sessions *SessionManager) *Authenticator {
	return &Authenticator{sessions: sessions, adminGroup: "homelab-admins", secure: true}
}
