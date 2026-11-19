package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TaliaMarine/dovecot-usermanager/internal/auth"
	"github.com/TaliaMarine/dovecot-usermanager/internal/hash"
	"github.com/TaliaMarine/dovecot-usermanager/internal/passwd"
)

type fakeUsers struct {
	file      *passwd.File
	restarted bool
}

func (f *fakeUsers) Users(context.Context) ([]string, error) { return f.file.Users(), nil }
func (f *fakeUsers) Mutate(_ context.Context, fn func(*passwd.File) error) error {
	return fn(f.file)
}
func (f *fakeUsers) Restart(context.Context) error { f.restarted = true; return nil }

func setup(t *testing.T) (http.Handler, *fakeUsers, *http.Cookie) {
	t.Helper()
	sm, _ := auth.NewSessionManager([]byte(strings.Repeat("k", 32)), true)
	// The Authenticator needs OIDC discovery; build a bare one for Require().
	a := auth.NewTestAuthenticator(sm)
	h, _ := hash.New(hash.SHA512Crypt)
	fu := &fakeUsers{file: passwd.Parse(nil)}
	srv, err := New(a, fu, h, "https://um.example/api/auth/callback", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	_ = sm.Issue(rec, "sub", "admin@tusca.be", "Admin")
	return srv.Handler(), fu, rec.Result().Cookies()[0]
}

func do(h http.Handler, method, path, body string, c *http.Cookie, csrf bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if c != nil {
		req.AddCookie(c)
	}
	if csrf {
		req.Header.Set(CSRFHeader, CSRFValue)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRequiresSession(t *testing.T) {
	h, _, _ := setup(t)
	for _, p := range []string{"/api/me", "/api/users"} {
		if r := do(h, "GET", p, "", nil, false); r.Code != 401 {
			t.Errorf("%s = %d", p, r.Code)
		}
	}
	if r := do(h, "GET", "/healthz", "", nil, false); r.Code != 200 {
		t.Errorf("healthz = %d", r.Code)
	}
}

func TestCSRF(t *testing.T) {
	h, fu, c := setup(t)
	if r := do(h, "POST", "/api/restart", "", c, false); r.Code != 403 || fu.restarted {
		t.Fatalf("no header: %d", r.Code)
	}
	req := httptest.NewRequest("POST", "/api/restart", nil)
	req.AddCookie(c)
	req.Header.Set(CSRFHeader, CSRFValue)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 || fu.restarted {
		t.Fatalf("bad origin: %d", rec.Code)
	}
	if r := do(h, "POST", "/api/restart", "", c, true); r.Code != 202 || !fu.restarted {
		t.Fatalf("restart: %d", r.Code)
	}
}

func TestUserLifecycle(t *testing.T) {
	h, fu, c := setup(t)

	r := do(h, "POST", "/api/users", `{"name":"t@tusca.be","generate":true}`, c, true)
	if r.Code != 201 {
		t.Fatalf("create = %d %s", r.Code, r.Body)
	}
	var resp map[string]string
	_ = json.Unmarshal(r.Body.Bytes(), &resp)
	if len(resp["password"]) != generatedLen {
		t.Fatalf("generated password = %q", resp["password"])
	}
	line := strings.TrimSpace(string(fu.file.Bytes()))
	if !strings.HasPrefix(line, "t@tusca.be:{SHA512-CRYPT}$6$") || strings.Contains(line, resp["password"]) {
		t.Fatalf("stored line = %q", line)
	}
	if !hash.Verify(resp["password"], strings.TrimPrefix(line, "t@tusca.be:")) {
		t.Fatal("stored hash does not match the generated password")
	}

	if r := do(h, "POST", "/api/users", `{"name":"t@tusca.be","password":"longenoughpw"}`, c, true); r.Code != 409 {
		t.Fatalf("dup = %d", r.Code)
	}
	if r := do(h, "POST", "/api/users", `{"name":"BAD","password":"longenoughpw"}`, c, true); r.Code != 400 {
		t.Fatalf("bad name = %d", r.Code)
	}
	if r := do(h, "POST", "/api/users", `{"name":"u@tusca.be","password":"short"}`, c, true); r.Code != 400 {
		t.Fatalf("short pw = %d", r.Code)
	}
	if r := do(h, "PUT", "/api/users/t@tusca.be/password", `{"password":"another-long-password"}`, c, true); r.Code != 200 {
		t.Fatalf("setpw = %d %s", r.Code, r.Body)
	}
	if r := do(h, "PUT", "/api/users/nobody@tusca.be/password", `{"password":"another-long-password"}`, c, true); r.Code != 404 {
		t.Fatalf("setpw missing = %d", r.Code)
	}
	if r := do(h, "GET", "/api/users", "", c, false); r.Code != 200 || !strings.Contains(r.Body.String(), "t@tusca.be") || strings.Contains(r.Body.String(), "SHA512") {
		t.Fatalf("list = %d %s", r.Code, r.Body)
	}
	if r := do(h, "DELETE", "/api/users/t@tusca.be", "", c, true); r.Code != 204 {
		t.Fatalf("delete = %d", r.Code)
	}
	if r := do(h, "DELETE", "/api/users/t@tusca.be", "", c, true); r.Code != 404 {
		t.Fatalf("delete again = %d", r.Code)
	}
}
