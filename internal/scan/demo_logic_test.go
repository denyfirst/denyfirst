package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The list matches at label boundaries, and the sloppy match fails open.
//
// The exclusion list matches this way too, and there a mistake keeps a host
// out that should be in. Here a mistake lets a host in that should be out,
// which is how somebody would arrange to have us scan them: register
// denyfirst.dev.example.com and a suffix match hands them our address.
func TestTheDemonstrationListMatchesAtLabelBoundaries(t *testing.T) {
	restore := demoTargets
	demoTargets = []string{"denyfirst.dev"}
	defer func() { demoTargets = restore }()

	for _, c := range []struct {
		host string
		want bool
	}{
		{"denyfirst.dev", true},
		{"tls10-only.denyfirst.dev", true},
		{"a.b.denyfirst.dev", true},
		{"DENYFIRST.DEV", true},
		{"denyfirst.dev.", true},
		{"  denyfirst.dev  ", true},

		{"denyfirst.dev.example.com", false},
		{"notdenyfirst.dev", false},
		{"xdenyfirst.dev", false},
		{"denyfirst.development", false},
		{"dev", false},
		{"example.com", false},
		{"", false},
		{".", false},
	} {
		if got := isDemoTarget(c.host); got != c.want {
			t.Errorf("isDemoTarget(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// An empty entry in the list does not admit everything.
//
// A blank line in a list is the kind of thing a bad merge leaves behind, and
// "" as a suffix matches every host there is.
func TestABlankEntryAdmitsNothing(t *testing.T) {
	restore := demoTargets
	demoTargets = []string{"", "  ", "."}
	defer func() { demoTargets = restore }()

	for _, host := range []string{"example.com", "denyfirst.dev", "a.b.c"} {
		if isDemoTarget(host) {
			t.Errorf("a list of blanks admitted %q", host)
		}
	}
}

// The build tag says which hosts may be reached and nothing else.
//
// Two builds of one program is a security boundary, and a boundary drawn by a
// build tag is only as narrow as the files carrying it. So two rules hold it.
//
// Every file under the tag is named demo_*.go, which makes the whole boundary
// greppable: somebody asking what the demonstration build changes can list it
// without reading the tree. And outside tests, the tag gates exactly the two
// files that declare the list — if it ever gates a third, the demonstration
// build has stopped being the tool with a list and become a different program
// that nobody runs the suite against.
func TestTheBuildTagTouchesNothingElse(t *testing.T) {
	declaring := map[string]bool{
		filepath.Join("internal", "scan", "demo_on.go"):  true,
		filepath.Join("internal", "scan", "demo_off.go"): true,
	}

	found := map[string]bool{}
	root := filepath.Join("..", "..")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "//go:build") {
				continue
			}
			if strings.Contains(line, "demo") {
				rel, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				found[rel] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	for path := range found {
		if name := filepath.Base(path); !strings.HasPrefix(name, "demo_") {
			t.Errorf("%s is gated on the demo build tag and is not named demo_*, so the "+
				"boundary can no longer be found by looking", path)
		}
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		if !declaring[path] {
			t.Errorf("%s is gated on the demo build tag, and outside tests only the two files "+
				"that declare the list may be", path)
		}
	}
	for path := range declaring {
		if !found[path] {
			t.Errorf("%s no longer carries the demo build tag, so the two builds may have merged", path)
		}
	}
}
