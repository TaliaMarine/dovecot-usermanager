// Package auth implements the OIDC login (Authorization Code + PKCE, public
// client) and encrypted cookie sessions.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const (
	sessionCookieName = "um_session"
	sessionTTL        = 12 * time.Hour
)

// Session is the authenticated admin carried in the encrypted cookie.
type Session struct {
	Subject   string    `json:"sub"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"exp"`
}

// Actor is the best human-readable identifier for audit logs.
func (s Session) Actor() string {
	if s.Email != "" {
		return s.Email
	}
	return s.Subject
}

// SessionManager seals sessions with AES-256-GCM (confidential + tamper-proof)
// so no server-side session store is needed.
type SessionManager struct {
	aead   cipher.AEAD
	secure bool
}

// MinKeyLen is the minimum accepted SESSION_KEY length.
const MinKeyLen = 32

func NewSessionManager(key []byte, secureCookies bool) (*SessionManager, error) {
	if len(key) < MinKeyLen {
		return nil, errors.New("session key must be at least 32 bytes")
	}
	sum := sha256.Sum256(key)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SessionManager{aead: aead, secure: secureCookies}, nil
}

func (m *SessionManager) seal(plain []byte) (string, error) {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(m.aead.Seal(nonce, nonce, plain, []byte(sessionCookieName))), nil
}

func (m *SessionManager) open(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < m.aead.NonceSize() {
		return nil, errors.New("malformed session")
	}
	n := m.aead.NonceSize()
	return m.aead.Open(nil, raw[:n], raw[n:], []byte(sessionCookieName))
}

// Issue sets a fresh session cookie.
func (m *SessionManager) Issue(w http.ResponseWriter, sub, email, name string) error {
	sess := Session{Subject: sub, Email: email, Name: name, ExpiresAt: time.Now().Add(sessionTTL)}
	payload, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	value, err := m.seal(payload)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: value, Path: "/", HttpOnly: true,
		Secure: m.secure, SameSite: http.SameSiteLaxMode, Expires: sess.ExpiresAt,
	})
	return nil
}

// FromRequest returns the valid session of r, if any.
func (m *SessionManager) FromRequest(r *http.Request) (Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return Session{}, false
	}
	plain, err := m.open(c.Value)
	if err != nil {
		return Session{}, false
	}
	var s Session
	if json.Unmarshal(plain, &s) != nil || time.Now().After(s.ExpiresAt) {
		return Session{}, false
	}
	return s, true
}

// Clear expires the session cookie.
func (m *SessionManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: m.secure, SameSite: http.SameSiteLaxMode,
	})
}
