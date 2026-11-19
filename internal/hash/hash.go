// Package hash produces Dovecot-compatible password hashes ("{SCHEME}...").
package hash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"golang.org/x/crypto/argon2"
)

// Supported schemes.
const (
	ARGON2ID    = "ARGON2ID"
	SHA512Crypt = "SHA512-CRYPT"
)

// Argon2id parameters. Memory is deliberately modest: Dovecot's auth worker
// re-allocates it on every login, and the pod has a small memory limit.
const (
	argonMemKiB  = 19456 // 19 MiB (OWASP minimum recommendation)
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// Hasher turns a clear-text password into a "{SCHEME}hash" string.
type Hasher interface {
	Scheme() string
	Hash(password string) (string, error)
}

// New returns a Hasher for the (case-insensitive) scheme name.
func New(scheme string) (Hasher, error) {
	switch strings.ToUpper(scheme) {
	case ARGON2ID:
		return argon2idHasher{}, nil
	case SHA512Crypt:
		return sha512Hasher{}, nil
	}
	return nil, fmt.Errorf("unsupported password scheme %q (use %s or %s)", scheme, ARGON2ID, SHA512Crypt)
}

type argon2idHasher struct{}

func (argon2idHasher) Scheme() string { return ARGON2ID }

func (argon2idHasher) Hash(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemKiB, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("{ARGON2ID}$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemKiB, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

type sha512Hasher struct{}

func (sha512Hasher) Scheme() string { return SHA512Crypt }

func (sha512Hasher) Hash(password string) (string, error) {
	salt := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	// crypt salts are limited to [./0-9A-Za-z]; derive them from random bytes.
	const alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	for i, b := range salt {
		salt[i] = alphabet[int(b)%len(alphabet)]
	}
	h, err := crypt.SHA512.New().Generate([]byte(password), []byte("$6$"+string(salt)))
	if err != nil {
		return "", err
	}
	return "{SHA512-CRYPT}" + h, nil
}

// Verify checks password against a "{SCHEME}hash" value. Used by tests and
// kept in the package so hashing and verification stay in sync.
func Verify(password, stored string) bool {
	switch {
	case strings.HasPrefix(stored, "{ARGON2ID}"):
		var m, t uint32
		var p uint8
		parts := strings.Split(strings.TrimPrefix(stored, "{ARGON2ID}"), "$")
		// "", argon2id, v=19, m=..,t=..,p=.., salt, key
		if len(parts) != 6 || parts[1] != "argon2id" {
			return false
		}
		if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
			return false
		}
		salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
		want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
		if err1 != nil || err2 != nil {
			return false
		}
		got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
		return subtle.ConstantTimeCompare(got, want) == 1
	case strings.HasPrefix(stored, "{SHA512-CRYPT}"):
		return crypt.SHA512.New().Verify(strings.TrimPrefix(stored, "{SHA512-CRYPT}"), []byte(password)) == nil
	}
	return false
}
