package scan

import (
	"errors"
	"strings"
)

// Excluded names are refused before anything connects to them.
//
// The list is short on purpose. A long one goes stale, and a long one that
// has gone stale says something worse than nothing: that this project decides
// which organisations deserve protection and got the answer wrong. What is
// here covers the cases where a scan would be misread as reconnaissance no
// matter how it was meant, and everything else is handled by asking.
//
// .gov is deliberately absent. Most of what sits under it is an ordinary
// public website that a citizen's browser connects to daily, and refusing to
// look at one would suggest this tool does something a government site needs
// protection from. It does not.
//
// Anyone who would rather not be scanned is added on request, from an address
// at the domain or one listed in its WHOIS or security.txt. That route is
// published on the site, needs no explanation, and is applied before the
// reply. It handles far more real cases than any list written in advance.
var excludedSuffixes = []string{
	// Military. A TLS handshake is harmless; a handshake against a defence
	// network, described afterwards by somebody who was not asked, is a
	// conversation this project has nothing to gain from.
	"mil",
	"mod.uk",

	// Intelligence and law enforcement.
	"cia.gov",
	"nsa.gov",
	"fbi.gov",
	"dni.gov",
	"nro.gov",
	"dia.mil",
	"mi5.gov.uk",
	"sis.gov.uk",
	"gchq.gov.uk",

	// Nuclear and space agencies, where an unexplained scan lands in front of
	// somebody whose job is to treat it seriously.
	"nasa.gov",
	"esa.int",
	"iaea.org",
	"energy.gov",
	"llnl.gov",
	"lanl.gov",
	"sandia.gov",

	// International bodies with their own security arrangements.
	"nato.int",
	"un.org",
	"interpol.int",
	"europol.europa.eu",
}

// extraExcluded holds names added by whoever runs this instance, from the
// exclusion requests that arrive by email.
//
// Kept separate from the list above so that a copy of this project starts
// with the same defaults and its operator's additions stay their own.
var extraExcluded []string

// ErrExcluded is returned for a name this instance will not scan.
var ErrExcluded = errors.New("this service does not scan that domain")

// Exclude adds names to the list for this process.
//
// Each entry matches the name itself and anything beneath it, at label
// boundaries. Call it before serving; it is not safe to call once requests
// are being handled.
func Exclude(names ...string) {
	for _, name := range names {
		name = strings.ToLower(strings.Trim(strings.TrimSpace(name), "."))
		if name != "" {
			extraExcluded = append(extraExcluded, name)
		}
	}
}

// IsExcluded reports whether a hostname is one this service refuses.
//
// Matching is at label boundaries rather than by string suffix. "mil" must
// exclude army.mil and not example.mil.com, and it must not exclude
// domil.com — a plain HasSuffix does the wrong thing on both counts, and the
// second is the one that would go unnoticed.
func IsExcluded(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}

	for _, suffix := range excludedSuffixes {
		if matchesSuffix(host, suffix) {
			return true
		}
	}
	for _, suffix := range extraExcluded {
		if matchesSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// matchesSuffix reports whether host is suffix, or sits beneath it.
func matchesSuffix(host, suffix string) bool {
	if host == suffix {
		return true
	}
	// The dot is what makes this a label boundary: "army.mil" ends with
	// ".mil" and "domil.com" does not end with anything of the sort.
	return strings.HasSuffix(host, "."+suffix)
}
