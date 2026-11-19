// Package passwd parses and rewrites a Dovecot passwd-file while leaving
// everything the app does not own (comments, blank lines, extra fields,
// unparsable lines) byte-for-byte intact.
package passwd

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// userRe: lowercase full address, local part [a-z0-9._+-]+, domain labels.
var userRe = regexp.MustCompile(`^[a-z0-9._+-]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

const maxUserLen = 254

// ValidateUser checks a username is a safe, lowercase full e-mail address.
func ValidateUser(name string) error {
	if len(name) > maxUserLen || !userRe.MatchString(name) {
		return errors.New("username must be a lowercase address like name@example.com ([a-z0-9._+-] local part)")
	}
	return nil
}

type line struct {
	raw  string
	name string // empty for lines the app does not manage
	hash string
	rest string // ":uid:gid:..." including the leading colon, or ""
}

// File is a parsed passwd-file.
type File struct {
	lines []line
}

// Parse reads passwd-file content.
func Parse(data []byte) *File {
	f := &File{}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return f
	}
	for _, raw := range strings.Split(text, "\n") {
		l := line{raw: raw}
		trimmed := strings.TrimSpace(raw)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			parts := strings.SplitN(raw, ":", 3)
			if len(parts) >= 2 && parts[0] != "" {
				l.name, l.hash = parts[0], parts[1]
				if len(parts) == 3 {
					l.rest = ":" + parts[2]
				}
			}
		}
		f.lines = append(f.lines, l)
	}
	return f
}

// Users returns the managed user names in file order.
func (f *File) Users() []string {
	var out []string
	for _, l := range f.lines {
		if l.name != "" {
			out = append(out, l.name)
		}
	}
	return out
}

// Has reports whether name exists.
func (f *File) Has(name string) bool { return f.find(name) >= 0 }

func (f *File) find(name string) int {
	for i, l := range f.lines {
		if l.name == name {
			return i
		}
	}
	return -1
}

// ErrExists / ErrNotFound are returned by Add / SetHash / Delete.
var (
	ErrExists   = errors.New("user already exists")
	ErrNotFound = errors.New("user not found")
)

// Add appends a new user. hash must be a complete "{SCHEME}..." value.
func (f *File) Add(name, hash string) error {
	if err := checkHash(hash); err != nil {
		return err
	}
	if f.Has(name) {
		return ErrExists
	}
	f.lines = append(f.lines, line{raw: name + ":" + hash, name: name, hash: hash})
	return nil
}

// SetHash replaces a user's password hash, keeping any extra fields.
func (f *File) SetHash(name, hash string) error {
	if err := checkHash(hash); err != nil {
		return err
	}
	i := f.find(name)
	if i < 0 {
		return ErrNotFound
	}
	l := &f.lines[i]
	l.hash = hash
	l.raw = l.name + ":" + hash + l.rest
	return nil
}

// Delete removes a user.
func (f *File) Delete(name string) error {
	i := f.find(name)
	if i < 0 {
		return ErrNotFound
	}
	f.lines = append(f.lines[:i], f.lines[i+1:]...)
	return nil
}

// Bytes renders the file with a trailing newline.
func (f *File) Bytes() []byte {
	if len(f.lines) == 0 {
		return nil
	}
	var b strings.Builder
	for _, l := range f.lines {
		b.WriteString(l.raw)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func checkHash(h string) error {
	if !strings.HasPrefix(h, "{") || !strings.Contains(h, "}") || strings.ContainsAny(h, ":\r\n \t") {
		return fmt.Errorf("invalid hash format")
	}
	return nil
}
