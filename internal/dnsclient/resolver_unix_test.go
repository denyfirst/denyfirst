//go:build !windows

package dnsclient

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeResolvConf points the reader at a file this test wrote, so the result
// describes the file rather than whatever the machine running the test is
// configured with.
func writeResolvConf(t *testing.T, body string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	was := resolvConf
	resolvConf = path
	t.Cleanup(func() { resolvConf = was })
}

// Every nameserver is read, in the order the file has them.
func TestEveryNameserverIsRead(t *testing.T) {
	writeResolvConf(t, strings.Join([]string{
		"# a comment",
		"; another",
		"search example.test",
		"nameserver 192.0.2.1",
		"options edns0",
		"nameserver 192.0.2.2",
		"nameserver 2001:db8::1",
	}, "\n"))

	got, err := systemResolvers()
	if err != nil {
		t.Fatalf("systemResolvers: %v", err)
	}

	want := []string{"192.0.2.1:53", "192.0.2.2:53", "[2001:db8::1]:53"}
	if len(got) != len(want) {
		t.Fatalf("read %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("resolver %d is %q, want %q; the order is the file's and a caller tries "+
				"them in it", i, got[i], want[i])
		}
	}
}

// An unusable address is skipped rather than returned as a resolver.
func TestAnUnusableNameserverIsSkipped(t *testing.T) {
	writeResolvConf(t, strings.Join([]string{
		"nameserver 0.0.0.0",
		"nameserver not-an-address",
		"nameserver",
		"nameserver 192.0.2.5",
	}, "\n"))

	got, err := systemResolvers()
	if err != nil {
		t.Fatalf("systemResolvers: %v", err)
	}
	if len(got) != 1 || got[0] != "192.0.2.5:53" {
		t.Errorf("read %v, want only the one usable address: a lookup sent to 0.0.0.0 spends "+
			"a timeout to learn nothing", got)
	}
}

// The list is bounded.
func TestTheNameserverListIsBounded(t *testing.T) {
	var lines []string
	for i := 1; i <= maxResolvers+4; i++ {
		lines = append(lines, "nameserver 192.0.2."+string(rune('0'+i%10)))
	}
	writeResolvConf(t, strings.Join(lines, "\n"))

	got, err := systemResolvers()
	if err != nil {
		t.Fatalf("systemResolvers: %v", err)
	}
	if len(got) > maxResolvers {
		t.Errorf("read %d resolvers, and the bound is %d; one lookup trying every entry of a "+
			"long file is a lookup that outlasts the scan", len(got), maxResolvers)
	}
}

// A file with no nameserver in it is no resolver, and says which it is.
func TestAFileWithNoNameserverIsNoResolver(t *testing.T) {
	writeResolvConf(t, "search example.test\noptions edns0\n")

	_, err := systemResolvers()
	if !errors.Is(err, ErrNoResolver) {
		t.Errorf("systemResolvers returned %v, want ErrNoResolver", err)
	}
}

// And a file that is not there is the same answer.
func TestAMissingResolvConfIsNoResolver(t *testing.T) {
	was := resolvConf
	resolvConf = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { resolvConf = was })

	_, err := systemResolvers()
	if !errors.Is(err, ErrNoResolver) {
		t.Errorf("systemResolvers returned %v, want ErrNoResolver", err)
	}
}
