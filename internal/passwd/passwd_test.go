package passwd

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateUser(t *testing.T) {
	ok := []string{"talia@tusca.be", "a.b+c_d-e@mail.example.com", "x1@a-b.co"}
	bad := []string{"", "talia", "Talia@tusca.be", "a:b@tusca.be", "a b@tusca.be", "a@b", "a@tusca.be\n", "@tusca.be", "a@-x.be", strings.Repeat("a", 250) + "@tusca.be"}
	for _, u := range ok {
		if err := ValidateUser(u); err != nil {
			t.Errorf("%q should be valid: %v", u, err)
		}
	}
	for _, u := range bad {
		if ValidateUser(u) == nil {
			t.Errorf("%q should be invalid", u)
		}
	}
}

const sample = "# managed by hand\n\nold@tusca.be:{SHA512-CRYPT}$6$x$y:1000:1000::/home/old\nweird line without colon\nb@tusca.be:{PLAIN}pw\n"

func TestRoundTripPreservesEverything(t *testing.T) {
	if got := string(Parse([]byte(sample)).Bytes()); got != sample {
		t.Fatalf("round trip changed content:\n%q", got)
	}
}

func TestUsers(t *testing.T) {
	got := Parse([]byte(sample)).Users()
	if len(got) != 2 || got[0] != "old@tusca.be" || got[1] != "b@tusca.be" {
		t.Fatalf("users = %v", got)
	}
}

func TestSetHashKeepsExtraFields(t *testing.T) {
	f := Parse([]byte(sample))
	if err := f.SetHash("old@tusca.be", "{ARGON2ID}$new"); err != nil {
		t.Fatal(err)
	}
	want := "old@tusca.be:{ARGON2ID}$new:1000:1000::/home/old"
	if !strings.Contains(string(f.Bytes()), want+"\n") {
		t.Fatalf("extra fields lost:\n%s", f.Bytes())
	}
	if !strings.HasPrefix(string(f.Bytes()), "# managed by hand\n\n") {
		t.Fatal("comments lost")
	}
}

func TestAddDelete(t *testing.T) {
	f := Parse(nil)
	if err := f.Add("a@x.be", "{S}h"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(f.Add("a@x.be", "{S}h"), ErrExists) {
		t.Fatal("want ErrExists")
	}
	if !errors.Is(f.SetHash("zz@x.be", "{S}h"), ErrNotFound) {
		t.Fatal("want ErrNotFound")
	}
	if err := f.Delete("a@x.be"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(f.Delete("a@x.be"), ErrNotFound) {
		t.Fatal("want ErrNotFound")
	}
	if f.Bytes() != nil {
		t.Fatal("empty file should render empty")
	}
}

func TestRejectsBadHash(t *testing.T) {
	f := Parse(nil)
	for _, h := range []string{"nohash", "{S}a:b", "{S}a\nb", "{S}a b"} {
		if f.Add("a@x.be", h) == nil {
			t.Errorf("hash %q accepted", h)
		}
	}
}
