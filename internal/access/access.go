// Package access closes an installation to whoever cannot sign in, and holds
// the key its kept data is encrypted with.
//
// One password, one operator. An installation keeps a history of which names
// it checked and what it found on them, which is a map of an estate's
// weaknesses, and a list of the domains somebody runs. Both are worth taking,
// so both are behind the password, and both are encrypted with a key that
// exists on disk only wrapped by it.
//
// The design, in the order it matters:
//
//   - The password is never written anywhere. What is kept is a random data
//     key, sealed with AES-256-GCM under a key derived from the password with
//     PBKDF2-SHA256. Opening the seal is the password check: a wrong password
//     fails authentication, and there is no separate hash to attack.
//   - The data key lives in memory from the first sign-in until the process
//     stops. A stolen disk, or a backup of it, holds only the sealed key and
//     data encrypted under it.
//   - A forgotten password cannot be recovered, by anyone. That is what the
//     encryption is for. Deleting the access file and restarting sets a new
//     password and a new key, and what was kept under the old one is
//     unreadable from then on.
//
// Everything here is the standard library: crypto/pbkdf2, crypto/aes,
// crypto/cipher. go.mod still has no require block.
package access

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Iterations is the PBKDF2 work factor: OWASP's figure for PBKDF2-SHA256.
// Each sign-in costs this once, which is the point.
const Iterations = 600_000

// workFactor is what seal uses and the least Unlock accepts. Iterations, except
// in this package's tests, which lower it so they do not spend minutes
// deriving keys.
var workFactor = Iterations

// MinPassword is the shortest password a person may choose. The one this
// package generates is longer.
const MinPassword = 12

// maxPassword bounds what is derived from. PBKDF2 hashes a long password
// down before it iterates, so a longer one costs nothing extra; the bound is
// on what a request body may carry.
const maxPassword = 256

// sealLabel is authenticated with the sealed key, so a sealed value from any
// other use of AES-GCM does not open as this one.
const sealLabel = "porch-access-v1"

// ErrWrongPassword is what a password that does not open the seal returns.
// It says nothing about how close it was.
var ErrWrongPassword = errors.New("that is not this installation's password")

// ErrWeakPassword is what a chosen password below MinPassword returns.
var ErrWeakPassword = fmt.Errorf("a password has to be at least %d characters", MinPassword)

// sealed is the access file. Base64 in JSON, by encoding/json's handling of
// []byte.
type sealed struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Key        []byte `json:"key"`
}

// GeneratePassword returns a password with 130 bits from the system's random
// source, in lowercase groups a person can read out: xxxxx-xxxxx-...
func GeneratePassword() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("a password could not be generated: %w", err)
	}
	text := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	var groups []string
	for len(text) > 0 {
		n := min(5, len(text))
		groups = append(groups, text[:n])
		text = text[n:]
	}
	return strings.Join(groups, "-"), nil
}

// Create writes a new access file sealing a new data key under password. It
// refuses to replace an existing file: replacing it would make everything
// kept under the old key unreadable, and that is a decision somebody makes by
// deleting the file, not a side effect.
func Create(path, password string) error {
	if err := checkLength(password); err != nil {
		return err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("a data key could not be generated: %w", err)
	}
	body, err := seal(key, password)
	if err != nil {
		return err
	}

	// #nosec G304 -- operator-supplied path, never request-supplied
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("the access file could not be created: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("the access file could not be written: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("the access file could not be written: %w", err)
	}
	return f.Close()
}

// Unlock opens the access file with password and returns the data key.
func Unlock(path, password string) ([]byte, error) {
	if len(password) == 0 || len(password) > maxPassword {
		return nil, ErrWrongPassword
	}
	// #nosec G304 -- operator-supplied path, never request-supplied
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the access file could not be read: %w", err)
	}
	var s sealed
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, errors.New("the access file is not one this program wrote")
	}
	if s.Version != 1 || s.KDF != "pbkdf2-sha256" || s.Iterations < workFactor ||
		len(s.Salt) != 16 || len(s.Nonce) != 12 {
		return nil, errors.New("the access file is not one this program wrote")
	}

	gcm, err := wrapper(password, s.Salt, s.Iterations)
	if err != nil {
		return nil, err
	}
	key, err := gcm.Open(nil, s.Nonce, s.Key, []byte(sealLabel))
	if err != nil || len(key) != 32 {
		return nil, ErrWrongPassword
	}
	return key, nil
}

// Change seals the same data key under a new password. What was kept stays
// readable, because the key it was encrypted with does not change.
//
// The file is replaced by a rename, so it is never half-written: a crash in
// the middle leaves the old password working rather than neither.
func Change(path, current, next string) error {
	if err := checkLength(next); err != nil {
		return err
	}
	key, err := Unlock(path, current)
	if err != nil {
		return err
	}
	body, err := seal(key, next)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".access-*")
	if err != nil {
		return fmt.Errorf("the new password could not be saved: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("the new password could not be saved: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("the new password could not be saved: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("the new password could not be saved: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("the new password could not be saved: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("the new password could not be saved: %w", err)
	}
	return nil
}

func checkLength(password string) error {
	if len([]rune(password)) < MinPassword {
		return ErrWeakPassword
	}
	if len(password) > maxPassword {
		return fmt.Errorf("a password may be at most %d bytes", maxPassword)
	}
	return nil
}

func seal(key []byte, password string) ([]byte, error) {
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("a salt could not be generated: %w", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("a nonce could not be generated: %w", err)
	}
	gcm, err := wrapper(password, salt, workFactor)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(sealed{
		Version:    1,
		KDF:        "pbkdf2-sha256",
		Iterations: workFactor,
		Salt:       salt,
		Nonce:      nonce,
		Key:        gcm.Seal(nil, nonce, key, []byte(sealLabel)),
	}, "", "  ")
}

// wrapper is the AES-GCM instance a password opens.
func wrapper(password string, salt []byte, iterations int) (cipher.AEAD, error) {
	kek, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return nil, fmt.Errorf("the password could not be derived: %w", err)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
