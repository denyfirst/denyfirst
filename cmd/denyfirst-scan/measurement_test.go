package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// The gate this command exists to be must not be openable by the host it is
// gating.
//
// A truncated cipher enumeration withdraws a strong verdict and returns
// ungraded, because a list that stopped early cannot support the claim that
// nothing weak is present. The host decides when to stop answering, so
// ungraded is a state it can choose. While it exited zero, that whole
// protection ended at the shell: answer twice, go quiet, and the pipeline
// went green.
func TestUngradedIsNotAPass(t *testing.T) {
	got := exitCode([]outcome{{Verdict: policy.Ungraded}})
	if got == exitOK {
		t.Fatal("a scan that graded nothing exited zero; a gate that cannot tell a pass from an absent result is not a gate")
	}
	if got != exitUngraded {
		t.Errorf("exitCode = %d, want %d", got, exitUngraded)
	}
}

// policy.Worst ignores ungraded entries, and it is right to: aggregating
// grades has to skip the things that are not grades. Reading the status off
// it alone therefore published a pass for a target nobody measured, hidden
// behind one that was fine.
func TestAnUngradedTargetIsNotHiddenByAGoodOne(t *testing.T) {
	got := exitCode([]outcome{
		{Verdict: policy.Strong},
		{Verdict: policy.Ungraded},
	})
	if got != exitUngraded {
		t.Errorf("exitCode = %d, want %d; the ungraded target vanished from the status", got, exitUngraded)
	}
}

// Severity still wins. An operator with one insecure target and one ungraded
// one has to be sent to the insecure one first.
func TestSeverityOutranksAnAbsentResult(t *testing.T) {
	cases := map[string]struct {
		outcomes []outcome
		want     int
	}{
		"insecure and ungraded": {[]outcome{
			{Verdict: policy.Insecure},
			{Verdict: policy.Ungraded},
		}, exitInsecure},
		"weak and ungraded": {[]outcome{
			{Verdict: policy.Weak},
			{Verdict: policy.Ungraded},
		}, exitWeak},
		"all strong": {[]outcome{
			{Verdict: policy.Strong},
			{Verdict: policy.Strong},
		}, exitOK},
		"a failure outranks everything": {[]outcome{
			{Verdict: policy.Strong},
			{Verdict: policy.Ungraded, Failed: true},
		}, exitError},
	}

	for name, tc := range cases {
		if got := exitCode(tc.outcomes); got != tc.want {
			t.Errorf("%s: exitCode = %d, want %d", name, got, tc.want)
		}
	}
}

// "Refused" is a claim about the server. Only one kind of failure earns it,
// and the probe already says which; this used to print the word for every
// failure and then print the contradicting sentence beside it.
func TestOnlyAServerRefusalIsCalledOne(t *testing.T) {
	report := &tlsprobe.Report{Versions: []tlsprobe.VersionResult{
		{Name: "TLS 1.3", Supported: true, Grade: policy.VersionFinding{Verdict: policy.Strong, Preferred: true}},
		{Name: "TLS 1.2", Supported: true, Grade: policy.VersionFinding{Verdict: policy.Strong}},
		{Name: "TLS 1.1", Refused: true, Error: "server refused TLS 1.1"},
		{Name: "TLS 1.0", Error: "not tested: this build of Go declined to offer TLS 1.0"},
	}}

	var out bytes.Buffer
	printVersions(&out, report)

	for _, line := range strings.Split(out.String(), "\n") {
		if !strings.Contains(line, "TLS 1.0") {
			continue
		}
		if strings.Contains(line, "refused") {
			t.Errorf("a version this client never offered is printed as refused by the server:\n  %s", line)
		}
		if !strings.Contains(line, "not measured") {
			t.Errorf("a version that was not measured does not say so:\n  %s", line)
		}
	}

	if !strings.Contains(out.String(), "TLS 1.1   refused") &&
		!strings.Contains(out.String(), "TLS 1.1    refused") {
		t.Errorf("a real server refusal stopped being called one:\n%s", out.String())
	}
}

// A heading reading "accepted" over a list that stopped early is read as the
// whole set, and the suites missing from it are the weak ones.
func TestATruncatedListSaysSoWhereItIsShown(t *testing.T) {
	suite := tlsprobe.CipherResult{
		CipherFinding: policy.GradeCipher("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
	}

	for _, tc := range []struct {
		name     string
		complete bool
		want     bool
	}{
		{"incomplete", false, true},
		{"complete", true, false},
	} {
		var out bytes.Buffer
		printCiphers(&out, &tlsprobe.Report{Versions: []tlsprobe.VersionResult{{
			Name: "TLS 1.2", Supported: true,
			Ciphers:            []tlsprobe.CipherResult{suite},
			CipherListComplete: tc.complete,
		}}})

		if got := strings.Contains(out.String(), "incomplete"); got != tc.want {
			t.Errorf("%s: the list is marked incomplete = %v, want %v\n%s", tc.name, got, tc.want, out.String())
		}
	}
}
