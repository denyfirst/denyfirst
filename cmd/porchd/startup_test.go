package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is porchd itself, run by the tests below as a separate
// process so that run() parses real flags. It does nothing when the test
// suite runs it.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("PORCHD_HELPER") != "1" {
		return
	}
	args := strings.Split(os.Getenv("PORCHD_ARGS"), "\n")
	os.Args = append([]string{"porchd"}, args...)
	os.Exit(run())
}

// start runs porchd with args and returns its exit code and what it said.
// Every case here is expected to stop before it listens.
func start(t *testing.T, args ...string) (int, string) {
	t.Helper()
	// Bounded: a porchd that does not refuse starts serving and never exits,
	// and that has to fail this test by name rather than by the suite's
	// ten-minute timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), "PORCHD_HELPER=1", "PORCHD_ARGS="+strings.Join(args, "\n"))
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Errorf("porchd started serving instead of refusing: %q", out)
		return -1, string(out)
	}
	if err == nil {
		return 0, string(out)
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode(), string(out)
	}
	t.Fatalf("porchd did not run: %v", err)
	return -1, ""
}

// Beyond loopback, porchd serves nobody without a password unless told so out
// loud (audit 2026-09-18, D01): proof of control says which domains may be
// checked, not who may ask.
func TestAPublicServiceWithoutAPasswordIsRefused(t *testing.T) {
	dir := t.TempDir()
	code, said := start(t, "-listen", "0.0.0.0:0", "-verification-secret-file", filepath.Join(dir, "secret"))
	if code != 2 || !strings.Contains(said, "without a password") {
		t.Errorf("a public service with proof and no password: exit %d, %q", code, said)
	}
	for _, listen := range []string{"127.0.0.1:0", "localhost:0", "[::1]:0"} {
		if err := passwordAllowed(listen, false, false); err != nil {
			t.Errorf("%s is loopback and was refused: %v", listen, err)
		}
	}
	if err := passwordAllowed("0.0.0.0:8080", true, false); err != nil {
		t.Errorf("a guarded service was refused: %v", err)
	}
	if err := passwordAllowed("0.0.0.0:8080", false, true); err != nil {
		t.Errorf("-without-password was not honoured: %v", err)
	}
}

// A password and a plain results directory together are refused, not one
// quietly winning (D02): the directory would keep in the clear, under each
// checked name, what the password is there to seal.
func TestAPasswordAndAPlainResultsDirectoryAreRefusedTogether(t *testing.T) {
	dir := t.TempDir()
	code, said := start(t, "-listen", "127.0.0.1:0",
		"-access-file", filepath.Join(dir, "access"),
		"-results-dir", filepath.Join(dir, "plain"))
	if code != 2 || !strings.Contains(said, "-results-dir keeps results in the clear") {
		t.Errorf("-access-file with -results-dir: exit %d, %q", code, said)
	}
	if _, err := os.Stat(filepath.Join(dir, "plain")); !os.IsNotExist(err) {
		t.Error("the refused results directory was made")
	}
}

// Every configuration this project hands out that listens beyond loopback
// carries a password: the compose file, the image, and every command block in
// the self-hosting guide. The guide's certificate example dropped it once,
// because a compose command replaces the default rather than adding to it.
func TestEveryShippedConfigurationCarriesAPassword(t *testing.T) {
	check := func(name, block string) {
		// The value after -listen, in the three spellings the project uses:
		// a YAML list item, a Dockerfile array, and -listen=value.
		value := regexp.MustCompile(`-listen(?:=|"\s*\n\s*-\s*"|",\s*")([^"\s]+)`).FindStringSubmatch(block)
		if value == nil {
			return
		}
		if host, _, err := net.SplitHostPort(value[1]); err == nil && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
			return
		}
		if !strings.Contains(block, `"-access-file"`) || !strings.Contains(block, `"/data/access"`) {
			t.Errorf("%s listens beyond loopback without -access-file:\n%s", name, block)
		}
	}
	check("docker-compose.yml", repoFile(t, "docker-compose.yml"))
	check("Dockerfile", repoFile(t, "Dockerfile"))

	guide := repoFile(t, "docs/self-host.md")
	blocks := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllStringSubmatch(guide, -1)
	found := 0
	for _, b := range blocks {
		if strings.Contains(b[1], "command:") {
			found++
			check("a command in docs/self-host.md", b[1])
		}
	}
	if found == 0 {
		t.Error("the guide has no command block, so this test checks nothing there")
	}
}

// Signed proof only is a setting on the proof, so it needs proof to be on, and
// when given it reaches the scope every check asks (A06).
func TestSignedProofOnlyNeedsProofAndReachesTheScope(t *testing.T) {
	code, said := start(t, "-listen", "127.0.0.1:0", "-verification-requires-dnssec")
	if code != 2 || !strings.Contains(said, "-verification-requires-dnssec needs -verification-secret-file") {
		t.Errorf("signed proof without proof: exit %d, %q", code, said)
	}
	src := repoFile(t, "cmd/porchd/main.go")
	set := strings.Index(src, "scope.RequireSigned = true")
	use := strings.Index(src, "serviceScanner(roots, scope, *resolver)")
	if set < 0 || use < 0 || set > use {
		t.Error("-verification-requires-dnssec is not set on the scope before the scanner is built")
	}
}
