package main

import (
	"os"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// A binary has to be able to say which release it is.
//
// -buildvcs=false is deliberate: the embedded VCS stamp varies with how the
// tree was fetched and would make two honest builds of one tag differ. The
// tag in the filename is lost the moment somebody renames or packages the
// file. So without a linked-in version, an operator holding this program has
// no way to check whether it is the build that fixed anything — which for a
// tool people run to answer security questions is not cosmetic.
//
// The failure mode this guards is silent. Rename the variable, or drop the
// flag from the build script, and every release from then on reports itself
// as unknown while every check stays green.
func TestTheBuildScriptStampsTheVersionSymbolThisProgramDefines(t *testing.T) {
	script, err := os.ReadFile("../../scripts/build.sh")
	if err != nil {
		t.Fatalf("reading the build script: %v", err)
	}

	const stamp = "-X main.version="
	if !strings.Contains(string(script), stamp) {
		t.Errorf("scripts/build.sh no longer contains %q, so a release would not know its own version", stamp)
	}

	// Both commands are package main and both are built by that script, so
	// both have to define the symbol it sets. Setting one that does not exist
	// is accepted silently by the linker.
	for _, path := range []string{"main.go", "../denyfirstd/main.go"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if !strings.Contains(string(body), "var version =") {
			t.Errorf("%s does not define `version`, and the build script sets it", path)
		}
	}
}

// A binary built any other way must not claim to be a release. The default
// says what it is instead.
func TestAnUnstampedBinaryDoesNotClaimAVersion(t *testing.T) {
	if version == "" {
		t.Fatal("version is empty; -version would print a blank line")
	}
	if !strings.Contains(version, "unknown") {
		t.Errorf("the default version is %q; a binary not built by the release script must say so", version)
	}
	if strings.HasPrefix(version, "v") {
		t.Errorf("the default version %q looks like a release tag", version)
	}
}

// The two versions answer different questions and both are printed. A report
// graded by one policy version is not comparable with a report graded by
// another, so the rule set is named beside the build.
func TestThePolicyVersionIsNotTheReleaseVersion(t *testing.T) {
	if policy.Version == version {
		t.Error("the policy version and the release version are the same string; one of them is not being reported")
	}
}
