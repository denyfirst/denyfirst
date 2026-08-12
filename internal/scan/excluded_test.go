package scan

import (
	"context"
	"strings"
	"testing"
)

func TestExcludedNamesAreRefused(t *testing.T) {
	excluded := []string{
		"army.mil",
		"navy.mil",
		"www.army.mil",
		"deeply.nested.army.mil",
		"cia.gov",
		"www.fbi.gov",
		"nasa.gov",
		"science.nasa.gov",
		"nato.int",
		"mod.uk",
		"www.mod.uk",
	}

	for _, host := range excluded {
		if !IsExcluded(host) {
			t.Errorf("IsExcluded(%q) = false, want true", host)
		}
	}
}

// The trap this list exists to avoid. A plain HasSuffix on "mil" excludes
// domil.com and misses nothing anybody would notice until somebody with an
// ordinary domain is refused for no reason.
func TestExclusionMatchesAtLabelBoundaries(t *testing.T) {
	allowed := []string{
		"domil.com",
		"april.com",
		"example.mil.com",  // .mil is not the last label
		"nasa.gov.example", // nor here
		"mynasa.gov.uk",
		"notnato.int.example.com",
		"militarysurplus.com",
		"example.com",
	}

	for _, host := range allowed {
		if IsExcluded(host) {
			t.Errorf("IsExcluded(%q) = true; the match is not at a label boundary", host)
		}
	}
}

// Most of what sits under .gov is an ordinary public website. Refusing to
// look at one would suggest this tool does something a government site needs
// protection from, which it does not.
func TestOrdinaryGovernmentSitesAreNotExcluded(t *testing.T) {
	for _, host := range []string{
		"www.gov.uk",
		"irs.gov",
		"weather.gov",
		"usa.gov",
		"e-gov.az",
	} {
		if IsExcluded(host) {
			t.Errorf("IsExcluded(%q) = true; only defence and intelligence names are on the list", host)
		}
	}
}

// A trailing dot is the fully qualified form of the same name, and case is
// not significant in DNS. Either would otherwise walk straight past the list.
func TestExclusionIgnoresCaseAndTrailingDot(t *testing.T) {
	for _, host := range []string{
		"ARMY.MIL",
		"army.mil.",
		"Army.Mil.",
		"WWW.CIA.GOV",
	} {
		if !IsExcluded(host) {
			t.Errorf("IsExcluded(%q) = false; DNS names are case-insensitive and may be fully qualified", host)
		}
	}
}

// Exclusion requests arrive by email and are added by whoever runs the
// instance. A copy of this project starts with the same defaults and its
// operator's additions stay their own.
func TestOperatorCanAddNames(t *testing.T) {
	before := len(extraExcluded)
	t.Cleanup(func() { extraExcluded = extraExcluded[:before] })

	if IsExcluded("asked-not-to.example") {
		t.Fatal("the name was already excluded, so this test proves nothing")
	}

	Exclude("asked-not-to.example", "  Another.Example.  ", "")

	if !IsExcluded("asked-not-to.example") {
		t.Error("an added name was not excluded")
	}
	if !IsExcluded("www.asked-not-to.example") {
		t.Error("an added name did not cover what sits beneath it")
	}
	if !IsExcluded("another.example") {
		t.Error("an added name was not normalised before being stored")
	}
	if IsExcluded("notasked-not-to.example") {
		t.Error("an added name matched outside a label boundary")
	}
}

// The check has to sit where the connection is made, not only where a request
// arrives. A guard in one caller disappears the moment a second is written.
func TestScannerRefusesExcludedNames(t *testing.T) {
	s := &Scanner{}

	for _, target := range []string{"army.mil", "www.cia.gov", "nasa.gov:443"} {
		_, err := s.Scan(context.Background(), target)
		if err == nil {
			t.Errorf("Scan(%s) was not refused", target)
			continue
		}
		if !strings.Contains(err.Error(), "does not scan") {
			t.Errorf("Scan(%s) failed for the wrong reason: %v", target, err)
		}
	}
}
