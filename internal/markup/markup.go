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

// Reference is one thing a page pointed at, reduced to what a report may carry.
//
// Only references a rule reads are recorded at all: one over plaintext, or one
// to an origin that is not the page's own. A page loading its own scripts from
// its own host produces nothing here, because nothing asks about that — and a
// field kept without a rule that reads it is a field to remove rather than keep
// for later (N7).
type Reference struct {
	Kind Kind `json:"kind"`

	// Host is the name the reference pointed at, with no scheme, no path, no
	// query and no userinfo. Empty where the address carried no host that
	// survived bounding, which is kept rather than dropped: the reference
	// existed either way.
	Host string `json:"host,omitempty"`

	// Plaintext records that the address began http://.
	Plaintext bool `json:"plaintext,omitempty"`

	// ThirdParty records that the host is not the page's own.
	//
	// Origin, not registrable domain: static.example.com is a different origin
	// from www.example.com, and subresource integrity and CORS both work on
	// origins. Treating a sibling subdomain as the page's own would report a
	// site as loading nothing from elsewhere while a browser treats it as
	// exactly that.
	ThirdParty bool `json:"thirdParty,omitempty"`

	// Integrity records that the element carried an integrity attribute.
	//
	// Only meaningful on a script or a stylesheet, which are the two elements
	// subresource integrity covers. Elsewhere it is false and nothing reads it.
	Integrity bool `json:"integrity,omitempty"`

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

	// References holds what the page pulls in that some rule reads: anything
	// over plaintext, and anything from an origin that is not the page's own.
	// Deduplicated and bounded.
	References []Reference `json:"references,omitempty"`

	// ReferencesTotal is how many such references the page made, before
	// deduplication and before the bound. A page pointing at one host forty
	// times and a page pointing at forty hosts are different situations and a
	// list alone cannot tell them apart.
	ReferencesTotal int `json:"referencesTotal,omitempty"`

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
// Read scans one page served by host.
//
// host is the name the page was fetched from, and it decides one thing: which
// references are somebody else's origin. An empty host means that question
// cannot be answered, so nothing is marked third-party and the rules that read
// that flag find nothing — silence rather than a guess, which is the safe
// direction (R4).
func Read(r io.Reader, host string) Facts {
	facts := Facts{Read: true}
	host = fold(host)

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
		// Only what a rule reads. A page loading its own scripts from its own
		// host is the ordinary case and nothing asks about it, so it is not
		// counted and not kept.
		if !ref.Plaintext && !ref.ThirdParty {
			return
		}

		facts.ReferencesTotal++
		if seen[ref] {
			return
		}
		if len(facts.References) >= maxReferences {
			facts.MoreThanListed = true
			return
		}
		seen[ref] = true
		facts.References = append(facts.References, ref)
	}

	s := &scanner{src: string(body)}
	for {
		tag, ok := s.next()
		if !ok {
			break
		}
		examine(tag, host, &facts, add)
	}

	return facts
}

// examine turns one start tag into whatever it establishes.
func examine(t tag, host string, facts *Facts, add func(Reference)) {
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
		// integrity is carried only where it means something. The two elements
		// subresource integrity covers are script and link, and recording it
		// on an image would invite a rule about a guarantee no browser makes.
		record(t.attr["src"], KindScript, true, hasIntegrity(t), host, add)
	case "iframe", "frame":
		record(t.attr["src"], KindFrame, true, false, host, add)
	case "embed":
		record(t.attr["src"], KindObject, true, false, host, add)
	case "object":
		record(t.attr["data"], KindObject, true, false, host, add)

	case "link":
		// Only the relations that fetch something a page then depends on.
		// rel="dns-prefetch" over http is not a subresource, and reporting it
		// as mixed content would be a finding about a hint.
		switch strings.ToLower(strings.TrimSpace(t.attr["rel"])) {
		case "stylesheet":
			record(t.attr["href"], KindStyle, true, hasIntegrity(t), host, add)
		case "preload", "modulepreload":
			record(t.attr["href"], KindScript, true, hasIntegrity(t), host, add)
		}

	case "img", "image":
		record(t.attr["src"], KindImage, false, false, host, add)
	case "audio", "video", "source", "track":
		record(t.attr["src"], KindMedia, false, false, host, add)

	case "form":
		// Not a subresource and not blocked: a browser warns and submits.
		// Whatever is typed into the form travels in the clear, which is the
		// one thing here that is about the visitor rather than the page.
		record(t.attr["action"], KindForm, false, false, host, add)
	}
}

// hasIntegrity reports whether an element carried a usable integrity attribute.
//
// Present and non-empty. `integrity=""` is the attribute spelled without a
// value, which a browser treats as no integrity at all — and a report crediting
// it would tell a site it has a guarantee its visitors do not get.
func hasIntegrity(t tag) bool {
	return strings.TrimSpace(t.attr["integrity"]) != ""
}

// record keeps a reference where some rule reads it.
//
// Two questions, asked separately because they are different facts. Is the
// address plaintext — which only an explicit http:// makes it, since a relative
// address inherits the page's scheme, "//host/x" inherits it too, and data:,
// blob: and about: fetch nothing over a network. And is the host somebody
// else's origin, which needs an absolute address to answer at all.
//
// Treating a relative address as either would report a correctly built page as
// mixed content or as loading from elsewhere, and a reader who has seen one
// false finding stops believing the true ones.
func record(value string, kind Kind, blocking, integrity bool, host string, add func(Reference)) {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)

	var (
		plaintext bool
		prefix    string
	)
	switch {
	case strings.HasPrefix(lower, "http://"):
		plaintext, prefix = true, "http://"
	case strings.HasPrefix(lower, "https://"):
		prefix = "https://"

	case strings.HasPrefix(value, "//"):
		// Scheme-relative, and worth reading rather than skipping. It inherits
		// the page's scheme — which is TLS, since this only reads a page
		// fetched over TLS — so it is never mixed content. It may well be
		// another origin, and "//cdn.example/jquery.js" is how a great many
		// older pages load their scripts. Those are exactly the pages least
		// likely to carry an integrity attribute, so dropping this form would
		// have missed the sites the rule is most for.
		prefix = "//"

	default:
		// Relative, or not a network address at all: same origin by
		// construction, or data:, blob: and about:, which fetch nothing.
		return
	}
	found := hostOf(value, prefix)

	add(Reference{
		Kind:       kind,
		Host:       found,
		Plaintext:  plaintext,
		ThirdParty: host != "" && found != "" && found != host,
		Integrity:  integrity,
		Blocking:   blocking && plaintext,
	})
}

// hostOf reduces an http address to the host, and keeps nothing else.
//
// Userinfo is dropped before anything is kept rather than after. "http://
// user:token@host/" is a credential in a page's markup, and a report that
// carried it would have published it to everyone the report is shown to —
// which is the exact failure this package was allowed to exist on condition of
// avoiding.
func hostOf(address, scheme string) string {
	rest := address[len(scheme):]

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

// fold reduces a name the way every other comparison in this project does (I7).
func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
