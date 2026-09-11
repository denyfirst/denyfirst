// Package markup reads a page's HTML and keeps none of it.
//
// This is the first thing in this project that reads a response body, and the
// reason it took this long is written in docs/scope.md: a body holds things a
// report must never carry — a key in a comment, a token in a script, a name in
// a template — and a report is a thing people paste into issue trackers. So the
// shape here is the one that argument allows and no more.
//
//   - **Nothing is stored.** Facts has nowhere to put markup, in the way
//     webprobe.Cookie has nowhere to put a cookie's value. What survives a call
//     is "a script was referenced over plaintext, at this host", never the
//     element that said so.
//
//   - **Hosts, never addresses.** A reference is reduced to its host before it
//     is kept. No path, no query, and no userinfo — a URL in somebody's markup
//     can carry a token in any of the three, and a report naming the host is
//     as actionable as one naming the address.
//
//   - **Nothing found here is ever fetched.** This reads what a page says it
//     loads. It does not load it. No path is constructed, no link followed, no
//     script retrieved: N7 is unchanged by this package, which is the point of
//     putting the reading here rather than in the prober.
//
//   - **Bounded and streamed.** At most MaxBytes, read through a limit rather
//     than into memory twice. Past the bound, Truncated says so and nothing
//     below it was seen.
//
// # Why a scanner and not a parser
//
// There is no HTML parser in the standard library, and this project has no
// third-party dependencies. Writing a conforming parser would be a large piece
// of security-sensitive code to hold nobody has asked for; what a check needs
// is the start tags and a few of their attributes, and that is a scanner.
//
// It follows that this sees less than a browser does, and the limit says so
// rather than the report implying otherwise (R4). Markup assembled by a script
// at run time is invisible here, because nothing here executes anything.
package markup

import (
	"io"
	"strings"
)

const (
	// MaxBytes is how much of one page is read.
	//
	// Truncated rather than refused, which is the opposite of what the
	// revocation and transparency checks do with an oversized answer — and the
	// difference is what "nothing found" would mean. There, refusing was the
	// safe reading, because a truncated list reads as a clean certificate. Here
	// the page is the evidence, and refusing a two-megabyte page would produce
	// a report with no findings for exactly the sites most likely to have
	// something: the big ones. So a page over the bound is read to the bound,
	// Truncated is set, and the report says absence below it establishes
	// nothing.
	MaxBytes = 1 << 20

	// maxReferences bounds what one page can put in a report. A page composed
	// to hold ten thousand distinct hosts is a page composed for this scanner.
	maxReferences = 32

	// maxHostLength bounds one host before it is kept. Longer than any real
	// name, short enough that a report stays a report.
	maxHostLength = 253
)

// Kind is what a reference was for, which decides what a browser does with it.
type Kind string

const (
	KindScript Kind = "script"
	KindStyle  Kind = "stylesheet"
	KindFrame  Kind = "frame"
	KindObject Kind = "object"
	KindImage  Kind = "image"
	KindMedia  Kind = "media"
	KindForm   Kind = "form"
)

// Reference is one plaintext thing a page pointed at, reduced to what a report
// may carry.
type Reference struct {
	Kind Kind `json:"kind"`

	// Host is the name the reference pointed at, with no scheme, no path, no
	// query and no userinfo. Empty where the address carried no host that
	// survived bounding, which is kept rather than dropped: the reference
	// existed either way.
	Host string `json:"host,omitempty"`

	// Blocking records that a browser refuses to load this one at all.
	//
	// The W3C Mixed Content specification divides plaintext subresources on a
	// secure page into two sets. Scripts, stylesheets, frames and plugin data
	// are "blockable": every current browser refuses them outright, so the
	// resource does not arrive and the page is running without it. Images and
	// media are "optionally-blockable": browsers upgrade or allow them, and
	// behaviour differs between them.
	//
	// The two are kept apart because they lead a reader to different places. A
	// blocked script is a broken page today. An image over plaintext is a
	// browser's decision, and reporting it as the same thing would be this
	// project deciding something a specification deliberately left open.
	Blocking bool `json:"blocking,omitempty"`
}

// Facts is what reading one page's markup established. There is no field here
// that could hold the page.
type Facts struct {
	// Read is true when a body was read at all. False and everything below is
	// silence rather than absence, which is the distinction R4 exists for.
	Read bool `json:"read"`

	// Truncated is true when the page was longer than MaxBytes. Nothing below
	// the bound was seen, so an empty list means "none in the part that was
	// read" and the report has to say so.
	Truncated bool `json:"truncated,omitempty"`

	// MetaCSP and MetaCSPReportOnly record a policy declared in the markup
	// rather than in a header.
	//
	// A browser applies both. Reading only the header reported a site with a
	// meta policy as having none — and then, because the framing rule treats a
	// policy as superseding X-Frame-Options, told it a second time that it was
	// missing protection it had. Two wrong sentences from one omission.
	MetaCSP           bool `json:"metaCSP,omitempty"`
	MetaCSPReportOnly bool `json:"metaCSPReportOnly,omitempty"`

	// Plaintext holds the references to http:// addresses, deduplicated by
	// kind and host and bounded.
	Plaintext []Reference `json:"plaintext,omitempty"`

	// PlaintextTotal is how many such references the page made, before
	// deduplication and before the bound. A page pointing at one host forty
	// times and a page pointing at forty hosts are different situations and a
	// list alone cannot tell them apart.
	PlaintextTotal int `json:"plaintextTotal,omitempty"`

	// MoreThanListed is true when distinct references were found past the
	// bound, so the list is a sample rather than the set.
	MoreThanListed bool `json:"moreThanListed,omitempty"`
}

// Read scans one page.
//
// It never returns an error. A body that stops early, a connection that dies
// mid-page and a page that is not HTML at all all produce what was seen up to
// that point with Read set — because the alternative is a failure to read
// arriving in a report as a page with nothing in it.
func Read(r io.Reader) Facts {
	facts := Facts{Read: true}

	body, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if len(body) > MaxBytes {
		facts.Truncated = true
		body = body[:MaxBytes]
	}
	// err is deliberately unused beyond this point: what was read is what is
	// reported, and a read that ended early is not a page without references.
	_ = err

	seen := map[Reference]bool{}
	add := func(ref Reference) {
		facts.PlaintextTotal++
		if seen[ref] {
			return
		}
		if len(facts.Plaintext) >= maxReferences {
			facts.MoreThanListed = true
			return
		}
		seen[ref] = true
		facts.Plaintext = append(facts.Plaintext, ref)
	}

	s := &scanner{src: string(body)}
	for {
		tag, ok := s.next()
		if !ok {
			break
		}
		examine(tag, &facts, add)
	}

	return facts
}

// examine turns one start tag into whatever it establishes.
func examine(t tag, facts *Facts, add func(Reference)) {
	switch t.name {
	case "meta":
		// http-equiv is the only form of this that a browser honours. A
		// <meta name="Content-Security-Policy"> is a comment with delusions
		// and must not be counted, or a report would credit a site with a
		// policy no browser applies.
		switch strings.ToLower(strings.TrimSpace(t.attr["http-equiv"])) {
		case "content-security-policy":
			facts.MetaCSP = true
		case "content-security-policy-report-only":
			facts.MetaCSPReportOnly = true
		}

	case "script":
		plaintext(t.attr["src"], KindScript, true, add)
	case "iframe", "frame":
		plaintext(t.attr["src"], KindFrame, true, add)
	case "embed":
		plaintext(t.attr["src"], KindObject, true, add)
	case "object":
		plaintext(t.attr["data"], KindObject, true, add)

	case "link":
		// Only the relations that fetch something a page then depends on.
		// rel="dns-prefetch" over http is not a subresource, and reporting it
		// as mixed content would be a finding about a hint.
		switch strings.ToLower(strings.TrimSpace(t.attr["rel"])) {
		case "stylesheet":
			plaintext(t.attr["href"], KindStyle, true, add)
		case "preload", "modulepreload":
			plaintext(t.attr["href"], KindScript, true, add)
		}

	case "img", "image":
		plaintext(t.attr["src"], KindImage, false, add)
	case "audio", "video", "source", "track":
		plaintext(t.attr["src"], KindMedia, false, add)

	case "form":
		// Not a subresource and not blocked: a browser warns and submits.
		// Whatever is typed into the form travels in the clear, which is the
		// one thing here that is about the visitor rather than the page.
		plaintext(t.attr["action"], KindForm, false, add)
	}
}

// plaintext records a reference when, and only when, it names an http address.
//
// Everything else is left alone deliberately. A relative address inherits the
// page's scheme, "//host/x" inherits it too, and data:, blob: and about: fetch
// nothing over a network. Treating any of them as plaintext would report a
// correctly built page as mixed content, which is the false alarm that makes a
// reader stop believing the true ones.
func plaintext(value string, kind Kind, blocking bool, add func(Reference)) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(strings.ToLower(value), "http://") {
		return
	}
	add(Reference{Kind: kind, Host: hostOf(value), Blocking: blocking})
}

// hostOf reduces an http address to the host, and keeps nothing else.
//
// Userinfo is dropped before anything is kept rather than after. "http://
// user:token@host/" is a credential in a page's markup, and a report that
// carried it would have published it to everyone the report is shown to —
// which is the exact failure this package was allowed to exist on condition of
// avoiding.
func hostOf(address string) string {
	rest := address[len("http://"):]

	// The authority ends at the first of these. Whatever follows is a path, a
	// query or a fragment and none of them is kept.
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}

	// Userinfo, if any, is everything before the last "@".
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}

	// A port says nothing a host does not, and an operator reading "example.com"
	// and "example.com:8080" as two findings is reading one.
	if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.Contains(rest[i:], "]") {
		rest = rest[:i]
	}
	rest = strings.Trim(rest, "[]")

	rest = strings.ToLower(strings.TrimSpace(rest))
	if len(rest) > maxHostLength {
		rest = rest[:maxHostLength]
	}

	// A host is chosen by whoever wrote the page, so it is stripped before it
	// travels (I5). A name carrying a newline would otherwise forge a line in
	// a terminal report.
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, rest)
}
