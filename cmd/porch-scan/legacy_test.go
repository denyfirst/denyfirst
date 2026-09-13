package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

func legacyOutput(t *testing.T, l tlsprobe.Legacy) (versions, suites string) {
	t.Helper()
	var v, s bytes.Buffer
	printLegacyVersion(&v, l)
	printLegacySuites(&s, l)
	return v.String(), s.String()
}

// SSL 3.0 is a version row, in the words every other row uses.
//
// "refused" only where the server sent an alert, "not measured" everywhere else.
// The column is the half a reader takes in, and a row saying "refused" over a
// connection that simply closed would be crediting the server with a decision
// it may never have made (R4).
func TestSSL3IsAVersionRowInTheSameWords(t *testing.T) {
	grade := policy.GradeVersion(policy.VersionSSL30)

	for name, tc := range map[string]struct {
		answer tlsprobe.LegacyAnswer
		want   []string
		never  []string
	}{
		"accepted": {
			answer: tlsprobe.LegacyAnswer{Measured: true, Accepted: true, Version: "SSL 3.0", VersionGrade: &grade},
			want:   []string{"SSL 3.0", "accepted", "insecure"},
			never:  []string{"refused", "not measured"},
		},
		"refused": {
			answer: tlsprobe.LegacyAnswer{Measured: true, Refused: true},
			want:   []string{"SSL 3.0", "refused"},
			never:  []string{"accepted", "not measured"},
		},
		"not measured": {
			answer: tlsprobe.LegacyAnswer{Reason: "the server did not answer in time"},
			want:   []string{"SSL 3.0", "not measured", "did not answer in time"},
			never:  []string{"refused", "accepted"},
		},
	} {
		versions, _ := legacyOutput(t, tlsprobe.Legacy{Asked: true, SSL3: tc.answer})
		for _, w := range tc.want {
			if !strings.Contains(versions, w) {
				t.Errorf("%s: the row does not carry %q: %q", name, w, versions)
			}
		}
		for _, n := range tc.never {
			if strings.Contains(versions, n) {
				t.Errorf("%s: the row says %q: %q", name, n, versions)
			}
		}
	}
}

// Nothing is printed for questions nobody asked.
func TestNothingIsPrintedForAQuestionNotAsked(t *testing.T) {
	versions, suites := legacyOutput(t, tlsprobe.Legacy{})
	if versions != "" || suites != "" {
		t.Errorf("a scan that asked nothing printed %q and %q", versions, suites)
	}
}

// What the hellos found is printed with the suite, the version, and the grade.
func TestTheHandWrittenHellosArePrintedWithWhatTheyFound(t *testing.T) {
	export := policy.GradeCipher("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA")
	l := tlsprobe.Legacy{
		Asked:    true,
		SSL3:     tlsprobe.LegacyAnswer{Measured: true, Refused: true},
		Export:   tlsprobe.LegacyAnswer{Measured: true, Accepted: true, Version: "TLS 1.0", Suite: &tlsprobe.CipherResult{CipherFinding: export}},
		Null:     tlsprobe.LegacyAnswer{Reason: "the server did not answer in time"},
		Fallback: tlsprobe.Fallback{Measured: true, Asked: "TLS 1.2"},
	}

	_, suites := legacyOutput(t, l)
	for _, want := range []string{
		"hand-written hello",
		"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA at TLS 1.0",
		"insecure",
		"not measured   the server did not answer in time",
		"not honoured",
		"claiming only TLS 1.2",
	} {
		if !strings.Contains(suites, want) {
			t.Errorf("the block does not carry %q:\n%s", want, suites)
		}
	}
}

// The report itself carries them, not only the helpers.
//
// The tests above call printLegacyVersion and printLegacySuites directly, so
// they pass whether or not the report prints them. This one goes through the
// two functions a scan actually calls.
func TestTheReportCarriesTheHandWrittenHellos(t *testing.T) {
	grade := policy.GradeVersion(policy.VersionSSL30)
	report := &tlsprobe.Report{Legacy: tlsprobe.Legacy{
		Asked:    true,
		SSL3:     tlsprobe.LegacyAnswer{Measured: true, Accepted: true, Version: "SSL 3.0", VersionGrade: &grade},
		Export:   tlsprobe.LegacyAnswer{Measured: true, Refused: true},
		Null:     tlsprobe.LegacyAnswer{Measured: true, Refused: true},
		Fallback: tlsprobe.Fallback{Reason: "not asked: the server accepts only one version"},
	}}

	var versions, ciphers bytes.Buffer
	printVersions(&versions, report)
	printCiphers(&ciphers, report)

	if !strings.Contains(versions.String(), "SSL 3.0") || !strings.Contains(versions.String(), "accepted") {
		t.Errorf("the version list does not carry SSL 3.0:\n%s", versions.String())
	}
	if !strings.Contains(ciphers.String(), "hand-written hello") {
		t.Errorf("the suites section does not carry what the hand-written hellos found:\n%s", ciphers.String())
	}
}
