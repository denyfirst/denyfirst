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
	"slices"
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

	// Plaintext records that the address, resolved as a browser resolves it,
	// is http.
	Plaintext bool `json:"plaintext,omitempty"`

	// ThirdParty records that the host is not the page's own.
	//
	// Origin, not registrable domain: static.example.com is a different origin
	// from www.example.com, and so is the page's own host over plaintext or on
	// another port. Subresource integrity and CORS both work on origins. Treating a sibling subdomain as the page's own would report a
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

	// Incomplete is true when reading stopped on an error before the page
	// ended: the connection closed, or the body did not decode. Like Truncated,
	// only the start of the page was seen.
	Incomplete bool `json:"incomplete,omitempty"`

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

// Read scans one page served by host.
//
// It never returns an error. A body that stops early, a connection that dies
// mid-page and a page that is not HTML at all all produce what was seen up to
// that point with Read set — because the alternative is a failure to read
// arriving in a report as a page with nothing in it. A read that stopped early
// sets Incomplete, so the report can say so.
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
	// What was read is still reported: a read that ended early is not a page
	// without references. It is a page of which only the start was seen, and
	// until the 2026-09-16 audit (A17) nothing said so.
	if err != nil {
		facts.Incomplete = true
	}

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

	// Where a relative address resolves: the page itself, until a base element
	// says otherwise.
	p := &page{host: host, base: origin{host: host}}

	s := &scanner{src: string(body)}
	for {
		tag, ok := s.next()
		if !ok {
			break
		}
		p.examine(tag, &facts, add)
	}

	return facts
}

// origin is where an address leads, reduced to what the rules ask about.
type origin struct {
	plaintext bool
	host      string

	// otherPort is true when the address named a port other than the one its
	// scheme defaults to. The page is fetched from https://host/, so a port —
	// like plaintext — makes a different origin even on the same host.
	otherPort bool
}

// page is what reading one page carries from one tag to the next.
type page struct {
	host string

	// base is where relative addresses resolve. The page's own origin, until
	// the first base element with an href: HTML uses that one and ignores the
	// rest, and an element before it was fetched against the page's address
	// already.
	base    origin
	baseSet bool
}

// examine turns one start tag into whatever it establishes.
func (p *page) examine(t tag, facts *Facts, add func(Reference)) {
	switch t.name {
	case "base":
		// The first one with an href, and only that one. A base pointing at
		// another origin moves every relative address after it there — and a
		// base over plaintext turns "app.js" into a plaintext script. Before
		// the 2026-09-16 audit (A17) it was not read at all.
		href, ok := t.attr["href"]
		if !ok || p.baseSet {
			return
		}
		p.baseSet = true
		if o, ok := p.resolve(href); ok {
			p.base = o
		}

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
		p.record(t.attr["src"], KindScript, true, hasIntegrity(t), add)
	case "iframe", "frame":
		p.record(t.attr["src"], KindFrame, true, false, add)
	case "embed":
		p.record(t.attr["src"], KindObject, true, false, add)
	case "object":
		p.record(t.attr["data"], KindObject, true, false, add)

	case "link":
		// Only the relations that fetch something a page then depends on.
		// rel="dns-prefetch" over http is not a subresource, and reporting it
		// as mixed content would be a finding about a hint. rel is a list of
		// words, so "preload stylesheet" is a stylesheet.
		rel := strings.Fields(strings.ToLower(t.attr["rel"]))
		switch {
		case slices.Contains(rel, "stylesheet"):
			p.record(t.attr["href"], KindStyle, true, hasIntegrity(t), add)
		case slices.Contains(rel, "preload"), slices.Contains(rel, "modulepreload"):
			p.record(t.attr["href"], KindScript, true, hasIntegrity(t), add)
		}

	case "img", "image":
		p.record(t.attr["src"], KindImage, false, false, add)
		p.recordSet(t.attr["srcset"], KindImage, add)
	case "source":
		// src inside audio and video, srcset inside picture.
		p.record(t.attr["src"], KindMedia, false, false, add)
		p.recordSet(t.attr["srcset"], KindImage, add)
	case "audio", "video", "track":
		p.record(t.attr["src"], KindMedia, false, false, add)

	case "form":
		// Not a subresource and not blocked: a browser warns and submits.
		// Whatever is typed into the form travels in the clear, which is the
		// one thing here that is about the visitor rather than the page.
		p.record(t.attr["action"], KindForm, false, false, add)
	case "button", "input":
		// formaction overrides the form's own action for the submission this
		// control makes, so it is a form action in its own right.
		p.record(t.attr["formaction"], KindForm, false, false, add)
	}
}

// hasIntegrity reports whether an element carried a non-empty integrity
// attribute.
//
// Present and non-empty. `integrity=""` is the attribute spelled without a
// value, which a browser treats as no integrity at all — and a report crediting
// it would tell a site it has a guarantee its visitors do not get. Whether the
// value is a well-formed hash of the file served is not checked: nothing here
// fetches the file.
func hasIntegrity(t tag) bool {
	return strings.TrimSpace(t.attr["integrity"]) != ""
}

// recordSet keeps each address in a srcset: candidates separated by commas,
// each an address followed by an optional descriptor.
//
// An address containing a comma is split by this where a browser would not.
// A piece left over is relative and names the base, which a rule reads only
// where the base is somebody else's.
func (p *page) recordSet(set string, kind Kind, add func(Reference)) {
	for _, candidate := range strings.Split(set, ",") {
		if fields := strings.Fields(candidate); len(fields) > 0 {
			p.record(fields[0], kind, false, false, add)
		}
	}
}

// record keeps a reference where some rule reads it.
//
// Two questions, asked separately because they are different facts. Does the
// address lead over plaintext, and is it somebody else's origin. Both are
// answered for the address as a browser resolves it — against the page, or
// against a base element — rather than for the text as written.
//
// Treating a relative address as either would report a correctly built page as
// mixed content or as loading from elsewhere, and a reader who has seen one
// false finding stops believing the true ones.
func (p *page) record(value string, kind Kind, blocking, integrity bool, add func(Reference)) {
	o, ok := p.resolve(value)
	if !ok {
		return
	}
	add(Reference{
		Kind:       kind,
		Host:       o.host,
		Plaintext:  o.plaintext,
		ThirdParty: p.host != "" && o.host != "" && (o.host != p.host || o.otherPort || o.plaintext),
		Integrity:  integrity,
		Blocking:   blocking && o.plaintext,
	})
}

// resolve says where an address leads, the way the URL standard reads it.
//
// ok is false where it leads nowhere a network fetch goes — no address at all,
// or data:, blob:, javascript: and the like.
//
// What a browser does before it reads an address, this does too: it trims
// spaces and control characters from both ends and drops every tab and newline
// inside, and for http and https a backslash is a slash. So "ht\ntp:\\host/"
// is http://host/, and before the 2026-09-16 audit (A17) it was a relative
// address on the page's own origin.
func (p *page) resolve(value string) (origin, bool) {
	value = strings.TrimFunc(value, func(r rune) bool { return r <= 0x20 })
	value = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(value)
	if value == "" {
		// An empty src fetches nothing; an empty action submits to the page
		// itself.
		return origin{}, false
	}

	scheme, rest, hasScheme := splitScheme(value)
	switch {
	case !hasScheme:
		rest = value
	case scheme == "http" || scheme == "https":
		plaintext := scheme == "http"
		if plaintext == p.base.plaintext && !isSlash(rest, 0) {
			// "https:app.js" against an https base is relative to it.
			return p.base, true
		}
		// Otherwise the authority follows, however many slashes precede it.
		return authority(strings.TrimLeft(rest, `/\`), plaintext), true
	default:
		return origin{}, false
	}

	// No scheme: relative to the base.
	if isSlash(rest, 0) && isSlash(rest, 1) {
		// Scheme-relative: the base's scheme, another authority.
		return authority(strings.TrimLeft(rest, `/\`), p.base.plaintext), true
	}
	return p.base, true
}

// splitScheme reads a URL scheme: a letter, then letters, digits, "+", "-" or
// ".", then a colon.
func splitScheme(value string) (scheme, rest string, ok bool) {
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		case i > 0 && c == ':':
			return strings.ToLower(value[:i]), value[i+1:], true
		default:
			return "", "", false
		}
	}
	return "", "", false
}

func isSlash(s string, i int) bool {
	return i < len(s) && (s[i] == '/' || s[i] == '\\')
}

// authority reduces what follows the slashes to an origin, and keeps nothing
// else.
//
// Userinfo is dropped before anything is kept rather than after. "http://
// user:token@host/" is a credential in a page's markup, and a report that
// carried it would have published it to everyone the report is shown to —
// which is the exact failure this package was allowed to exist on condition of
// avoiding.
func authority(rest string, plaintext bool) origin {
	// The authority ends at the first of these. Whatever follows is a path, a
	// query or a fragment and none of them is kept.
	if i := strings.IndexAny(rest, `/\?#`); i >= 0 {
		rest = rest[:i]
	}

	// Userinfo, if any, is everything before the last "@".
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}

	// A port is not kept in the name: an operator reading "example.com" and
	// "example.com:8080" as two findings is reading one. Whether it is the
	// scheme's own port is kept, because another port is another origin.
	o := origin{plaintext: plaintext}
	if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.Contains(rest[i:], "]") {
		port := strings.TrimLeft(rest[i+1:], "0")
		defaultPort := "443"
		if plaintext {
			defaultPort = "80"
		}
		o.otherPort = port != "" && port != defaultPort
		rest = rest[:i]
	}
	rest = strings.Trim(rest, "[]")

	rest = fold(rest)
	if len(rest) > maxHostLength {
		rest = rest[:maxHostLength]
	}

	// A host is chosen by whoever wrote the page, so it is stripped before it
	// travels (I5). A name carrying a newline would otherwise forge a line in
	// a terminal report.
	o.host = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, rest)
	return o
}

// fold reduces a name the way every other comparison in this project does (I7).
func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
