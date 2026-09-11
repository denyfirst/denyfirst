package policy

import (
	"sort"
	"strconv"
	"strings"
)

// The rules for what a secure page loads.
//
// The first rules in this project that rest on a response body, and the line
// they draw is the one every other section here draws: grade where a
// specification settles the consequence, report everything else.
//
// It happens to be an unusually clean line for this subject. The W3C Mixed
// Content specification does not advise — it divides plaintext subresources on
// a secure page into two sets and says what a user agent does with each.
// Scripts, stylesheets, frames and plugin data are *blockable*: a browser
// refuses them, so the resource does not arrive and the page is running without
// it. Images and media are *optionally-blockable*, and what a browser does with
// those is deliberately left open, so this project says what it saw and stops
// there (R21).
//
// A form is neither. A browser submits it, with a warning, so what is typed
// into it travels in the clear — which is the only rule here that is about the
// visitor rather than about the page.
var mixedContent = Reference{
	"W3C — Mixed Content",
	"https://www.w3.org/TR/mixed-content/",
}

// ContentFacts is what reading a secure page's markup established.
//
// A separate struct from HeaderFacts because these are answers to a different
// question over different evidence, and because the zero value has to mean
// "nothing was read" rather than "nothing was found". Read is what keeps the
// two apart.
type ContentFacts struct {
	// Read is true when the page was read at all. Everything below is silence
	// rather than absence without it (R4).
	Read bool

	// Truncated is true when the page ran past the bound. Nothing below it was
	// seen, so an empty list is "none in the part that was read".
	Truncated bool

	// Blocking, Passive and Forms are the plaintext references found, each
	// already reduced to a host by internal/markup. No path, no query, no
	// userinfo, and no markup.
	Blocking []string
	Passive  []string
	Forms    []string

	// MoreThanListed is true when the page held more distinct references than
	// the bound allows, so the lists are a sample rather than the set.
	MoreThanListed bool
}

// GradeContent applies the rules above.
func GradeContent(f ContentFacts) WebResult {
	var out WebResult

	if !f.Read {
		// Nothing at all, deliberately. A deployment that reads no body has
		// established nothing about what a page loads, and the sentence saying
		// so belongs with the header rules, which say it once — see
		// GradeHeaders. Repeating it here would put two versions of one
		// admission in one report.
		return out
	}

	// ── graded ──

	// A browser refuses these outright, so the page is running without them.
	// Not an opinion about how a site should be built: the specification says
	// what a user agent does, and what it does is not load the resource.
	if len(f.Blocking) > 0 {
		out.add(Finding{
			RuleID:  "content.mixed-blocked",
			Verdict: Weak,
			Title:   "The page loads resources over plaintext that a browser refuses",
			Rationale: "This page is served over TLS and asks for " + count(len(f.Blocking), "resource") +
				" over plain HTTP: " + namedHosts(f.Blocking) + ". Scripts, stylesheets, frames and plugin " +
				"data are blockable mixed content, which every current browser refuses rather than " +
				"downgrades — so the resources do not arrive and the page runs without them. Before " +
				"browsers blocked it this was a way to replace a page's own script from the network; " +
				"now it is a page that is broken in a way its author may not have seen, because a " +
				"blocked subresource fails quietly.",
			References: []Reference{mixedContent, owaspHeaders},
		})
	}

	// The one rule here about the visitor rather than the page. A browser
	// submits it: whatever was typed goes out in the clear.
	if len(f.Forms) > 0 {
		out.add(Finding{
			RuleID:  "content.form-posts-in-the-clear",
			Verdict: Insecure,
			Title:   "A form on this page submits over plaintext",
			Rationale: "The page is served over TLS and carries " + count(len(f.Forms), "form") +
				" whose action is a plain HTTP address: " + namedHosts(f.Forms) + ". A browser submits it, " +
				"with a warning, so whatever a visitor types — a password, a card number, a message " +
				"— travels in the clear and can be read and altered by anyone on the path. The lock " +
				"in the address bar is about the page and says nothing about where the form goes.",
			References: []Reference{mixedContent, owaspHeaders},
		})
	}

	// ── reported ──

	// Optionally-blockable content, and the reason it is not graded is the
	// specification rather than a judgement about severity. Browsers upgrade
	// some of these, block others, and differ from each other; a verdict would
	// be this project deciding something a standards body deliberately left
	// open (R21), and it would land on a site whose behaviour depends on which
	// browser the visitor uses.
	if len(f.Passive) > 0 {
		out.observe("The page asks for " + count(len(f.Passive), "image or media file") +
			" over plain HTTP: " + namedHosts(f.Passive) + ". These are optionally-blockable mixed " +
			"content: a browser may upgrade the request to HTTPS, may block it, or may load it, " +
			"and they do not all do the same thing. Where one is loaded, somebody on the path " +
			"chooses what the visitor sees. It is not graded because what happens depends on the " +
			"browser rather than on this server.")
	}

	// A sample that does not say it is one is a list a reader treats as the
	// set, and then fixes four things believing they were four.
	if f.MoreThanListed {
		out.observe("More plaintext references were found than are listed above, so what is named " +
			"is a sample rather than the whole set.")
	}

	// Past the bound nothing was seen, and an empty list must not read as a
	// clean page (R4).
	if f.Truncated {
		out.unsettled("The page was longer than this check reads and the rest was not examined, so " +
			"anything it loads further down was not established either way.")
	}

	return out
}

// count writes "one script" or "3 scripts", so a sentence reads as English at
// one and does not say "1 forms".
func count(n int, noun string) string {
	if n == 1 {
		return "one " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// namedHosts names the hosts, sorted, so two scans of an unchanged page produce the
// same sentence.
//
// A report that reorders itself between runs is a diff a reader has to work out
// is not a change, which is the argument the recommended-headers list already
// makes about its own order.
func namedHosts(hosts []string) string {
	named := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h == "" {
			// A reference whose address carried no host that survived
			// bounding. It existed, so it is counted; there is nothing to
			// name.
			continue
		}
		named = append(named, h)
	}
	if len(named) == 0 {
		return "no host in any of them could be read"
	}

	sort.Strings(named)
	if len(named) == 1 {
		return named[0]
	}
	return strings.Join(named[:len(named)-1], ", ") + " and " + named[len(named)-1]
}
