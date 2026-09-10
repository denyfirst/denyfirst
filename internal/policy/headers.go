package policy

import (
	"fmt"
	"strings"
)

// The response header rules.
//
// The probe has collected thirteen headers since the check shipped and two of
// them were read. What follows reads the rest, and the line it draws is the
// same one the cookie rules draw: grade where the scan settles the
// consequence and no correct configuration produces it, report everything
// else.
//
// That line puts almost all of the well-known "security headers" on the
// reported side, and it is worth being plain about why, because a reader
// comparing this report against a commercial scanner will notice. Those tools
// award points and letter grades against thresholds they wrote themselves. A
// threshold nobody published is one nobody can argue with, which means nobody
// can correct it either, and it survives into a report telling somebody their
// correct decision is a fault. This project would rather report less and be
// worth reading.
//
// Reported is not hidden. The headers a site does not send are listed in one
// sentence, once, with what each one does — which is the list somebody closing
// gaps actually works from. What they are not given is a verdict that pretends
// a missing Permissions-Policy is a defect.
var (
	fetchSpec = Reference{
		"WHATWG Fetch — X-Content-Type-Options and CORS protocol",
		"https://fetch.spec.whatwg.org/",
	}
	owaspHeaders = Reference{
		"OWASP — HTTP Security Response Headers Cheat Sheet",
		"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
	}
)

// HeaderFacts is one response, reduced to what the rules read.
//
// The response is the last one a browser would land on over TLS. These headers
// apply to the response that carries them rather than persisting like a
// transport policy, so the one that matters is the one whose content a visitor
// actually receives — not the last that happened to carry a header, which is
// what Strict-Transport-Security needs and why the two are chosen differently.
type HeaderFacts struct {
	// Answered records that a response was reached over TLS at all. Without
	// one there is nothing to say: an empty list of headers from a host that
	// never answered is not a host that sends no headers (R4).
	Answered bool

	// Present names every header of interest that the response carried.
	Present map[string]bool

	// ACAO and ACAC are the two CORS values whose combination a browser
	// refuses. Kept as values rather than as presence, because it is what
	// they say that decides it.
	ACAO string
	ACAC string
}

// recommended are the headers listed when a response does not carry them, and
// what each one does.
//
// Ordered deliberately, most consequential first, and iterated in that order
// rather than sorted afterwards. A list that reorders itself between two scans
// of an unchanged server is a diff a reader has to work out is not a change,
// and alphabetising it would put the two that decide most in the middle.
var recommended = []struct {
	Name string
	Does string
}{
	{"Content-Security-Policy", "limits where a page may load scripts and other resources from, which is what contains an injection once one exists"},
	{"X-Frame-Options", "decides whether another site may frame this one, which is what a clickjacking attack needs"},
	{"Referrer-Policy", "decides how much of this page's address is sent to sites it links to"},
	{"Permissions-Policy", "declines browser capabilities this site does not use, such as the camera or geolocation"},
	{"Cross-Origin-Opener-Policy", "separates this page from other windows that opened it"},
	{"Cross-Origin-Resource-Policy", "decides which sites may load this response as a resource"},
}

// GradeHeaders reads the response a visitor lands on.
func GradeHeaders(f HeaderFacts) WebResult {
	var out WebResult

	if !f.Answered {
		out.unsettled("Nothing answered over TLS, so what this host sends on a response was not " +
			"established here. That is different from sending nothing.")
		return out
	}

	// ── graded ──

	// A wildcard origin together with credentials. The Fetch specification
	// forbids the combination and a browser refuses the response outright, so
	// the site has neither the sharing it configured nor the restriction it
	// would have had by saying nothing.
	if strings.TrimSpace(f.ACAO) == "*" && strings.EqualFold(strings.TrimSpace(f.ACAC), "true") {
		out.add(Finding{
			RuleID:     "headers.cors-wildcard-with-credentials",
			Verdict:    Weak,
			Title:      "The CORS headers contradict each other and are refused",
			Rationale:  "Access-Control-Allow-Origin is * and Access-Control-Allow-Credentials is true. A browser refuses that combination rather than choosing between them, so no cross-origin request with credentials succeeds — the sharing this site configured does not work, and nothing about the response says so. A site that means to share with credentials names the origins; a site that means to share publicly does not send the credentials header.",
			References: []Reference{fetchSpec, owaspHeaders},
		})
	}

	// ── reported ──
	//
	// One sentence rather than six. A report that lists six absences
	// separately, on every scan, is a report a reader learns to skip — and
	// each of these is a header a correctly configured site can legitimately
	// not send.

	var missing []string
	for _, h := range recommended {
		if !f.Present[h.Name] {
			// Content-Security-Policy: frame-ancestors supersedes
			// X-Frame-Options, so a site with a policy is not missing framing
			// protection and must not be told it is (R6).
			if h.Name == "X-Frame-Options" && f.Present["Content-Security-Policy"] {
				continue
			}
			missing = append(missing, h.Name+" — "+h.Does)
		}
	}

	if len(missing) > 0 {
		out.observe(fmt.Sprintf("%d headers a site can send and this response did not. None of them is "+
			"required by any specification, and a correct site can legitimately send none: what each one "+
			"buys depends on what the site does, which a scan of one response cannot see. They are listed "+
			"so that somebody closing gaps has the list rather than a grade. %s.",
			len(missing), strings.Join(missing, "; ")))
	}

	// Content sniffing, reported rather than graded, and this one was written
	// as a finding first.
	//
	// The argument for grading it is good: nosniff has no effect on a response
	// whose Content-Type is already correct and is the whole difference on one
	// that is not, so unlike a missing frame-ancestors or a missing HttpOnly
	// there is no configuration that wants it absent. That is not the same as
	// a consequence this scan establishes. Whether the absence matters depends
	// on content types nothing here looked at, and a finding whose rationale
	// has to end with "and we did not establish that this matters" is a
	// finding grading an implication rather than a measurement (R17).
	//
	// The contrast that settles it is hsts.absent, which is graded: there the
	// consequence follows from the scan alone, because the scan established
	// that the plaintext address is reachable.
	if !f.Present["X-Content-Type-Options"] {
		out.observe("X-Content-Type-Options: nosniff was not sent. Without it a browser may disregard " +
			"the declared Content-Type and decide for itself what a response is, so a file served with " +
			"the wrong type — an upload, an error page, a generated document — can be treated as script " +
			"or as markup. Unlike most of the headers above there is no arrangement that wants this one " +
			"absent: it changes nothing about a response whose type is already correct. It is reported " +
			"rather than graded because whether it matters here depends on content this scan did not " +
			"read.")
	}

	// A policy that is present but reported-only tells a browser nothing.
	// Stated rather than graded: a site midway through writing a policy
	// legitimately runs it in report-only mode, which is what the mode is for.
	if f.Present["Content-Security-Policy-Report-Only"] && !f.Present["Content-Security-Policy"] {
		out.observe("A Content-Security-Policy is sent in report-only mode and not in enforcing mode. " +
			"A browser reports violations and blocks nothing, which is what the mode is for during a " +
			"rollout and is not protection yet.")
	}

	return out
}
