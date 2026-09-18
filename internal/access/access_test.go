package access

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The tests derive keys dozens of times; at the real work factor that is
// minutes. The factor is lowered for the package's tests only, and one test
// below checks the real one is what the program uses.
func TestMain(m *testing.M) {
	workFactor = 1000
	os.Exit(m.Run())
}

func accessFile(t *testing.T, password string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access")
	if err := Create(path, password); err != nil {
		t.Fatal(err)
	}
	return path
}

// The program derives at OWASP's figure, and never less than it asks for.
func TestTheWorkFactorIsOWASPs(t *testing.T) {
	if Iterations < 600_000 {
		t.Errorf("PBKDF2-SHA256 at %d iterations; OWASP's figure is 600,000", Iterations)
	}
	src, err := os.ReadFile("access.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "var workFactor = Iterations\n") {
		t.Error("the work factor the program uses is not Iterations")
	}
}

// The right password opens the key; a wrong one does not, and says only that.
func TestOnlyThePasswordOpensTheKey(t *testing.T) {
	path := accessFile(t, "correct horse battery")

	key, err := Unlock(path, "correct horse battery")
	if err != nil || len(key) != 32 {
		t.Fatalf("the right password did not open a 32-byte key: %v", err)
	}
	again, _ := Unlock(path, "correct horse battery")
	if !bytes.Equal(key, again) {
		t.Error("the same password opened two different keys")
	}
	for _, wrong := range []string{"", "correct horse batter", "Correct horse battery", strings.Repeat("x", 300)} {
		if _, err := Unlock(path, wrong); !errors.Is(err, ErrWrongPassword) {
			t.Errorf("%q: got %v, want ErrWrongPassword", wrong, err)
		}
	}
}

// Nothing on disk is the password or the key.
//
// What a stolen disk holds is the salt, the nonce and the sealed key; the
// password is nowhere, and the key is only there encrypted.
func TestThePasswordAndTheKeyAreNotOnDisk(t *testing.T) {
	path := accessFile(t, "correct horse battery")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := Unlock(path, "correct horse battery")
	if bytes.Contains(body, []byte("correct horse battery")) || bytes.Contains(body, key) {
		t.Error("the access file carries the password or the key")
	}
	var s sealed
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(s.Key, key) {
		t.Error("the sealed key contains the key in the clear")
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("the access file is readable by others: %v", info.Mode().Perm())
	}
}

// A file somebody altered does not open, and one with a weaker work factor
// is refused rather than trusted.
func TestAnAlteredFileDoesNotOpen(t *testing.T) {
	path := accessFile(t, "correct horse battery")
	body, _ := os.ReadFile(path)
	var s sealed
	_ = json.Unmarshal(body, &s)

	for name, change := range map[string]func(*sealed){
		"a byte of the key": func(s *sealed) { s.Key[0] ^= 1 },
		"the salt":          func(s *sealed) { s.Salt[0] ^= 1 },
		"the nonce":         func(s *sealed) { s.Nonce[0] ^= 1 },
		"fewer iterations":  func(s *sealed) { s.Iterations = workFactor - 1 },
		"another version":   func(s *sealed) { s.Version = 2 },
	} {
		c := s
		c.Key = append([]byte(nil), s.Key...)
		c.Salt = append([]byte(nil), s.Salt...)
		c.Nonce = append([]byte(nil), s.Nonce...)
		change(&c)
		altered, _ := json.Marshal(c)
		if err := os.WriteFile(path, altered, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Unlock(path, "correct horse battery"); err == nil {
			t.Errorf("a file with %s altered opened", name)
		}
	}
}

// A new file never replaces an old one: that would make everything kept under
// the old key unreadable, as a side effect.
func TestAnAccessFileIsNeverReplacedByCreate(t *testing.T) {
	path := accessFile(t, "correct horse battery")
	if err := Create(path, "another long password"); err == nil {
		t.Fatal("Create replaced an existing access file")
	}
	if _, err := Unlock(path, "correct horse battery"); err != nil {
		t.Errorf("the original password no longer opens the file: %v", err)
	}
}

// Changing the password keeps the key, so what was kept stays readable, and
// the old password stops working.
func TestChangingThePasswordKeepsTheKey(t *testing.T) {
	path := accessFile(t, "correct horse battery")
	before, _ := Unlock(path, "correct horse battery")

	if err := Change(path, "wrong password here", "a new long password"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("a change with the wrong current password: %v", err)
	}
	if err := Change(path, "correct horse battery", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("a change to a short password: %v", err)
	}
	if err := Change(path, "correct horse battery", "a new long password"); err != nil {
		t.Fatal(err)
	}
	after, err := Unlock(path, "a new long password")
	if err != nil || !bytes.Equal(before, after) {
		t.Errorf("the new password does not open the same key: %v", err)
	}
	if _, err := Unlock(path, "correct horse battery"); !errors.Is(err, ErrWrongPassword) {
		t.Error("the old password still opens the file")
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".access-*"))
	if len(leftovers) != 0 {
		t.Errorf("a change left temporary files behind: %v", leftovers)
	}
}

// A generated password is long, random and readable aloud.
func TestAGeneratedPasswordIsLongAndReadable(t *testing.T) {
	a, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GeneratePassword()
	if a == b {
		t.Error("two generated passwords are the same")
	}
	if !regexp.MustCompile(`^[a-z2-7]{5}(-[a-z2-7]{5}){5}(-[a-z2-7]{2})$`).MatchString(a) {
		t.Errorf("a generated password is not groups of the base32 alphabet: %q", a)
	}
	if err := checkLength(a); err != nil {
		t.Errorf("a generated password is refused: %v", err)
	}
}

// A file sealed at fewer iterations than the program uses is refused, even
// with the right password: a weaker file dropped in place of the real one
// must not become the thing a guesser attacks.
func TestAFileSealedAtALowerWorkFactorIsRefused(t *testing.T) {
	saved := workFactor
	workFactor = saved / 2
	path := accessFile(t, "correct horse battery")
	workFactor = saved

	if _, err := Unlock(path, "correct horse battery"); err == nil {
		t.Error("a file sealed at half the work factor opened")
	}
}
