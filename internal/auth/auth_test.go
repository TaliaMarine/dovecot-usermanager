package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHasGroup(t *testing.T) {
	if !HasGroup([]string{"a", "homelab-admins"}, "homelab-admins") || HasGroup([]string{"homelab-users"}, "homelab-admins") || HasGroup(nil, "x") {
		t.Fatal("HasGroup wrong")
	}
}

func TestSafeReturn(t *testing.T) {
	cases := map[string]string{
		"/": "/", "/x?y=1": "/x?y=1", "": "/", "//evil.com": "/", "https://evil.com": "/",
		"/\\evil.com": "/", "/api/users": "/", "/a\r\nSet-Cookie: x": "/",
	}
	for in, want := range cases {
		if got := SafeReturn(in); got != want {
			t.Errorf("SafeReturn(%q)=%q want %q", in, got, want)
		}
	}
}

func newMgr(t *testing.T) *SessionManager {
	m, err := NewSessionManager([]byte(strings.Repeat("k", 32)), true)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSessionRoundTrip(t *testing.T) {
	m := newMgr(t)
	rec := httptest.NewRecorder()
	if err := m.Issue(rec, "sub1", "t@tusca.be", "Talia"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	s, ok := m.FromRequest(req)
	if !ok || s.Email != "t@tusca.be" || s.Actor() != "t@tusca.be" {
		t.Fatalf("got %+v ok=%v", s, ok)
	}
	if strings.Contains(rec.Result().Cookies()[0].Value, "tusca") {
		t.Fatal("session cookie is not encrypted")
	}
}

func TestSessionTamperAndWrongKey(t *testing.T) {
	m := newMgr(t)
	rec := httptest.NewRecorder()
	_ = m.Issue(rec, "s", "e", "n")
	c := rec.Result().Cookies()[0]

	bad := *c
	bad.Value = c.Value[:len(c.Value)-2] + "AA"
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&bad)
	if _, ok := m.FromRequest(req); ok {
		t.Fatal("tampered cookie accepted")
	}

	other, _ := NewSessionManager([]byte(strings.Repeat("z", 32)), true)
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	if _, ok := other.FromRequest(req); ok {
		t.Fatal("cookie accepted under another key")
	}
}

func TestSessionExpired(t *testing.T) {
	m := newMgr(t)
	val, _ := m.seal([]byte(`{"sub":"s","exp":"` + time.Now().Add(-time.Minute).Format(time.RFC3339) + `"}`))
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: val})
	if _, ok := m.FromRequest(req); ok {
		t.Fatal("expired session accepted")
	}
}

func TestShortKeyRejected(t *testing.T) {
	if _, err := NewSessionManager([]byte("short"), true); err == nil {
		t.Fatal("short key accepted")
	}
}
