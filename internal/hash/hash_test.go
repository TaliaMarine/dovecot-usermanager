package hash

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	for _, scheme := range []string{ARGON2ID, SHA512Crypt, "argon2id"} {
		h, err := New(scheme)
		if err != nil {
			t.Fatal(err)
		}
		out, err := h.Hash("correct horse battery")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(out, "{"+h.Scheme()+"}") || strings.ContainsAny(out, ": \n") {
			t.Fatalf("%s: bad format %q", scheme, out)
		}
		if !Verify("correct horse battery", out) || Verify("wrong", out) {
			t.Fatalf("%s: verify mismatch for %q", scheme, out)
		}
		again, _ := h.Hash("correct horse battery")
		if again == out {
			t.Fatalf("%s: salt not random", scheme)
		}
	}
}

func TestUnknownScheme(t *testing.T) {
	if _, err := New("MD5"); err == nil {
		t.Fatal("expected error")
	}
}

// Known SHA512-CRYPT vector produced by OpenSSL: guards interop.
func TestSHA512KnownVector(t *testing.T) {
	// openssl passwd -6 -salt saltsalt password
	const v = "{SHA512-CRYPT}$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	if !Verify("password", v) {
		t.Fatal("known vector failed")
	}
}
