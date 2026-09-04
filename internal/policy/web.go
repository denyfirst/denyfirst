package policy

import (
	"fmt"
	"strconv"
	"strings"
)

// WebVersion identifies the rule set behind every verdict about how a website
// is reached. It is separate from TLSVersion, and separate on purpose.
//
// The two grade different evidence. A TLS verdict comes from a handshake; a
// web verdict comes from an HTTP response, which half the ports this project
// scans do not have. Folding them into one version would mean a rule about a
// header changing the number printed on a mail server's report, and two
// reports of the same host becoming incomparable for a reason that has
// nothing to do with what changed.
//
// v2, 2026-09-05. Two verdicts change, in the same direction and for the
// same reason: this rule set said nothing where it had measured something.
//
// A correctly reached site was graded ungraded, which means "nothing was
// established" and is what an unreachable host gets. The check had in fact
// established a great deal — that the policy is sound, that nothing answers
// in the clear — and reporting that as an absence made a correct site
// indistinguishable from one that never answered, on a command line where
// the exit status is the whole product.
//
// And a host that answered nothing over TLS was graded weak for declaring no
// policy, which is a claim about a server this program never spoke to.
//
// v1, 2026-09-04. The first rule set for this check: how a name answers on
// each scheme, and what it says about coming back over TLS.
const WebVersion = "denyfirst-web-v2"

// WebReviewBy is when these rules are read against their references again.
//
// Sooner than the TLS set's date, and for a reason written into the rules
// below: the cookie and same-site specification is approved and waiting for a
// number, and RFC 6797 predates every HTTPS-first default browsers now ship.
// A rule set resting on a document that is about to change its own identity
// needs a date, not an intention.
const WebReviewBy = "2026-12-01"

var (
	rfc6797 = Reference{"RFC 6797 — HTTP Strict Transport Security", "https://www.rfc-editor.org/rfc/rfc6797"}
	rfc9110 = Reference{"RFC 9110 — HTTP Semantics", "https://www.rfc-editor.org/rfc/rfc9110"}

	// Not a standards body. The preload list is a browser programme with
	// published entry requirements, which is a different kind of claim from
	// an RFC and is labelled as one: a site can be perfectly configured and
	// deliberately outside it.
	hstsPreload = Reference{"HSTS preload list — submission requirements", "https://hstspreload.org/"}

	owaspHSTS = Reference{"OWASP — HTTP Strict Transport Security Cheat Sheet",
		"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"}
)

// preloadMinAge is the max-age the preload list requires: one year.
//
// It is used to describe a header, never to grade one. OWASP's cheat sheet
// recommends a short max-age during a rollout and publishes no minimum, and
// no standards body publishes one either — so a rule failing anything under a
// year would be this project inventing a threshold and then penalising a
// deliberate, correct choice, which R6 forbids. The number appears in a note
// that says what it is: the bar for one browser programme.
const preloadMinAge = 31536000

// WebHop is one request in a chain, reduced to what these rules read.
//
// The web probe records more than this. Grading takes a copy of the little it
// needs rather than the whole structure, so that this package keeps its one
// unusual property: it imports nothing of this project's own, and a rule can
// be read without reading a probe.
type WebHop struct {
	// TLS is whether this hop was made over TLS.
	TLS bool

	// Answered is whether a response arrived at all. A hop that did not
	// answer carries no status and is not evidence about configuration.
	Answered bool

	// Status is the HTTP status code, when one arrived.
	Status int
}

// WebResult is a graded set of observations about one subject.
type WebResult struct {
	// Verdict is the worst of the findings below. Ungraded means nothing was
	// measured, which is not the same as nothing being wrong.
	Verdict Verdict `json:"verdict,omitempty"`

	Findings []Finding `json:"findings,omitempty"`
	Notes    []Note    `json:"notes,omitempty"`
}

func (r *WebResult) add(f Finding) {
	f.Policy = WebVersion
	r.Findings = append(r.Findings, f)
	r.Verdict = Worst(r.Verdict, f.Verdict)
}

func (r *WebResult) observe(text string) {
	r.Notes = append(r.Notes, Note{Kind: KindObserved, Text: text})
}

func (r *WebResult) unsettled(text string) {
	r.Notes = append(r.Notes, Note{Kind: KindUnsettled, Text: text})
}

// GradeReach grades how a name answers on each scheme.
//
// This is the question a TLS report cannot answer and does not claim to. A
// host can negotiate TLS 1.3 with an immaculate certificate and still hand
// every visitor's first request to whoever is on the path, because the
// address a person types has no scheme in it and the browser tries plaintext.
//
// secure is the chain that began at https://host/, plain the chain that began
// at http://host/. Either may be empty, which is itself an observation.
func GradeReach(secure, plain []WebHop) WebResult {
	var out WebResult

	secureLanded := landed(secure)
	plainLanded := landed(plain)

	// The secure side first, because everything else is read against it. A
	// name that does not answer over TLS is not a website being graded for
	// how it redirects; it is a different report.
	switch {
	case secureLanded == nil:
		out.unsettled("Nothing answered over TLS, so what a visitor reaches on the secure address " +
			"was not established here. Whether the handshake itself succeeds is a question for the " +
			"TLS check.")
	case !secureLanded.TLS:
		out.add(Finding{
			RuleID:     "reach.downgrades-to-plaintext",
			Verdict:    Insecure,
			Title:      "The secure address sends visitors to a plaintext one",
			Rationale:  "A request to the https address ends on an http address, so everything the visitor sends and receives after that point travels in the clear and can be read or altered by anyone on the path. The redirect undoes the protection the visitor asked for.",
			References: []Reference{rfc6797, rfc9110},
		})
	}

	// Whether anything was measured at all. Everything below can add a
	// finding; only this decides whether silence means "sound" or "unknown".
	//
	// The second half is a lock on a door that is already shut: a chain that
	// landed on a plaintext hop always raises reach.downgrades-to-plaintext
	// above, so the verdict is never silent there and the Strong below cannot
	// be reached anyway. A sabotage removing it changed no test, and it is
	// kept rather than simplified because the thing it guards - a site that
	// ends on plaintext being called sound - is the worst answer this rule
	// set could give, and it should not depend on a finding elsewhere staying
	// where it is.
	measured := secureLanded != nil && secureLanded.TLS

	// The plaintext side.
	switch {
	case plainLanded == nil:
		out.observe("Nothing answered on port 80. There is then no plaintext request to intercept, " +
			"and a visitor who types the name without a scheme reaches this site only if their " +
			"browser tries TLS first or already holds a policy that says to.")

	case plainLanded.TLS:
		// The chain started on http and finished on https: correct. What
		// remains worth saying is how it got there.
		if viaPlaintext(plain) {
			out.add(Finding{
				RuleID:     "reach.redirect-via-plaintext",
				Verdict:    Weak,
				Title:      "The move to TLS takes more than one step",
				Rationale:  "A visitor arriving on the plaintext address makes a further cleartext request before reaching the secure one. Each of those is a request an attacker on the path can answer instead, so the redirect that was meant to protect the visitor is itself unprotected.",
				References: []Reference{rfc6797},
			})
		}
		if first := firstAnswer(plain); first != nil && temporary(first.Status) {
			out.observe(fmt.Sprintf("The redirect from the plaintext address is temporary (%d) rather "+
				"than permanent. A browser may repeat the cleartext request on every visit instead of "+
				"remembering, which matters where no policy tells it to use TLS in the first place.",
				first.Status))
		}

	case plainLanded.Status >= 200 && plainLanded.Status < 300:
		out.add(Finding{
			RuleID:     "reach.plaintext-served",
			Verdict:    Insecure,
			Title:      "The site answers on the plaintext address",
			Rationale:  "Port 80 returns a page rather than sending the visitor to the secure address. Everything on it, and everything the visitor sends back, travels in the clear; anyone on the path can read it, change it, or serve a page of their own in its place, and the visitor sees nothing wrong.",
			References: []Reference{rfc6797, owaspHSTS},
		})

	case redirectStatus(plainLanded.Status):
		out.add(Finding{
			RuleID:     "reach.never-reaches-tls",
			Verdict:    Insecure,
			Title:      "The plaintext address redirects, but never arrives at TLS",
			Rationale:  "The chain of redirects from port 80 was still on plaintext when it ended, so a visitor following it never reaches the secure address. The redirects give the appearance of a site that moves visitors to TLS without doing it.",
			References: []Reference{rfc6797},
		})

	default:
		out.add(Finding{
			RuleID:     "reach.plaintext-not-redirected",
			Verdict:    Weak,
			Title:      "The plaintext address answers, and does not send visitors to TLS",
			Rationale:  fmt.Sprintf("Port 80 answered %d rather than redirecting. Nothing is served in the clear, but nothing moves a visitor who typed the name without a scheme to the secure address either, and the request that revealed which site they wanted was already sent in the clear.", plainLanded.Status),
			References: []Reference{rfc6797},
		})
	}

	// Silence is not a verdict on its own. Where the secure address answered
	// over TLS and nothing above was wrong, this rule set has established
	// that a visitor reaches the site the way they should - which is a
	// finding of soundness and has to be said as one.
	//
	// Until 2026-09-05 it was not. A correctly configured site came back
	// ungraded, which is what a host that never answered comes back as, and
	// on a command line whose exit status is the whole product the two were
	// the same number.
	if measured && out.Verdict == Ungraded {
		out.Verdict = Strong
	}

	return out
}

// HSTS is a parsed Strict-Transport-Security header.
type HSTS struct {
	// Parsed is whether a max-age was found. A header without one is ignored
	// in full by a browser, so nothing else in here means anything when this
	// is false.
	Parsed bool

	MaxAge            int64
	IncludeSubDomains bool
	Preload           bool
}

// ParseHSTS reads the first Strict-Transport-Security header.
//
// The first, and not a merge of all of them: RFC 6797 section 8.1 says a user
// agent that receives more than one processes only the first. Grading the
// most generous of several would describe a policy no browser applies.
func ParseHSTS(value string) HSTS {
	var out HSTS

	for _, directive := range strings.Split(value, ";") {
		name, arg, _ := strings.Cut(strings.TrimSpace(directive), "=")

		// Directive names are case-insensitive; the argument may be a quoted
		// string. Both are in the grammar, and a parser that misses either
		// reports a correct header as broken.
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "max-age":
			arg = strings.Trim(strings.TrimSpace(arg), `"`)
			n, err := strconv.ParseInt(arg, 10, 64)
			if err != nil || n < 0 {
				continue
			}
			// The first max-age wins, as it does in the grammar.
			if !out.Parsed {
				out.MaxAge = n
				out.Parsed = true
			}
		case "includesubdomains":
			out.IncludeSubDomains = true
		case "preload":
			out.Preload = true
		}
	}
	return out
}

// GradeHSTS grades the policy a site declares for coming back over TLS.
//
// secure holds the Strict-Transport-Security headers of the response a
// visitor lands on over TLS, and plain those of the response on port 80. Both
// are needed because sending the header only where a browser ignores it is a
// distinct and common mistake, and one nothing else in a report would show.
//
// secureAnswered says whether any response arrived over TLS at all, and it is
// a separate argument because no list of headers can carry the difference. A
// host that answered nothing and a host that answered without the header both
// produce an empty slice, and until 2026-09-05 both were graded weak for
// declaring no policy - a claim about a server this program had never spoken
// to.
func GradeHSTS(secure, plain []string, secureAnswered bool) WebResult {
	var out WebResult

	if !secureAnswered {
		out.unsettled("Nothing answered over TLS, so what this host declares about coming back " +
			"over TLS was not established here. That is different from declaring nothing.")
		return out
	}

	if len(secure) == 0 {
		if len(plain) > 0 {
			out.add(Finding{
				RuleID:     "hsts.plaintext-only",
				Verdict:    Weak,
				Title:      "The policy is sent only where no browser will act on it",
				Rationale:  "Strict-Transport-Security appears on the plaintext response and not on the secure one. RFC 6797 requires a browser to ignore the header unless it arrives over a secure transport, so this site is declaring a policy that has no effect anywhere, while appearing to be configured.",
				References: []Reference{rfc6797},
			})
			return out
		}
		out.add(Finding{
			RuleID:     "hsts.absent",
			Verdict:    Weak,
			Title:      "No policy tells a browser to come back over TLS",
			Rationale:  "Without Strict-Transport-Security, a visitor who types the name, follows an old link, or is redirected by someone else can be sent to the plaintext address, and an attacker on the path can keep them there. Browsers that try TLS first narrow this, but that is a property of the browser rather than of this server, and it does not survive an active attacker who answers the first request.",
			References: []Reference{rfc6797, owaspHSTS},
		})
		return out
	}

	if len(secure) > 1 {
		out.observe(fmt.Sprintf("%d Strict-Transport-Security headers were sent. A browser processes "+
			"only the first, so the first is what is graded here and the rest have no effect.", len(secure)))
	}

	p := ParseHSTS(secure[0])

	switch {
	case !p.Parsed:
		out.add(Finding{
			RuleID:     "hsts.unparseable",
			Verdict:    Weak,
			Title:      "The policy carries no valid max-age, so it is ignored",
			Rationale:  "Strict-Transport-Security is present but has no max-age a browser can read, and a browser that cannot read max-age discards the whole header. The site is configured for a protection it does not have, which is worse than being configured for none: nothing about it looks wrong.",
			References: []Reference{rfc6797},
		})
		return out

	case p.MaxAge == 0:
		out.add(Finding{
			RuleID:     "hsts.disabled",
			Verdict:    Weak,
			Title:      "The policy is set to expire immediately",
			Rationale:  "max-age=0 tells a browser to forget any policy it holds for this host. That is the correct way to withdraw one, and its effect is that there is no policy: a visitor's first request can be sent in the clear and kept there.",
			References: []Reference{rfc6797},
		})
		return out
	}

	// Everything below describes a working policy rather than grading it.
	// There is no published minimum max-age: OWASP recommends a short one
	// during a rollout, and no standards body sets a floor. A rule inventing
	// one would fail a site for a deliberate and correct choice.
	out.observe(fmt.Sprintf("The policy lasts %s. A browser that has not visited within that time "+
		"has forgotten it, and its next first request is unprotected again.", humanAge(p.MaxAge)))

	if p.IncludeSubDomains {
		out.observe("The policy covers subdomains.")
	} else {
		out.observe("The policy does not cover subdomains. Whether that matters depends on what else " +
			"exists beneath this name, which a scan of one host cannot see: an attacker able to answer " +
			"for any name under it can serve plaintext there and set cookies that this host will send.")
	}

	// A policy was read and it works. Said rather than left as silence, for
	// the reason given in GradeReach.
	out.Verdict = Worst(out.Verdict, Strong)

	if p.Preload && (p.MaxAge < preloadMinAge || !p.IncludeSubDomains) {
		out.add(Finding{
			RuleID:     "hsts.preload-ineffective",
			Verdict:    Weak,
			Title:      "Preloading is requested but the requirements are not met",
			Rationale:  "The preload directive asks browser vendors to ship this host in their list, which is the only thing that protects a visitor's very first request. The submission requirements are a max-age of at least one year and includeSubDomains, and this policy does not meet them, so the request cannot be accepted and the protection it was asked for does not exist.",
			References: []Reference{hstsPreload, rfc6797},
		})
	} else if p.MaxAge < preloadMinAge {
		out.observe(fmt.Sprintf("The policy is shorter than the one year the preload list requires, so "+
			"this host could not be submitted to it as configured. That is a bar for one browser "+
			"programme and not a standard; %s may be exactly what was intended.", humanAge(p.MaxAge)))
	}

	return out
}

// WebStandingLimits are true of every web check this program runs.
//
// They say nothing about the host in front of them, which is why they are
// separate from the TLS set rather than added to it: what a TLS scan cannot
// establish and what a header check cannot establish are different lists, and
// one list read under both headings is a list nobody reads.
func WebStandingLimits() []StandingLimit {
	return []StandingLimit{
		{
			ID:    "web-root-only",
			Title: "Only the root was asked, and only its headers were read",
			Text: "One request was made, to the root of the site, and only the response headers were " +
				"read. Another page on this site may answer with different headers, and nothing here " +
				"describes the content of any page.",
		},
		{
			ID:    "web-no-browser",
			Title: "No browser ran here",
			Text: "This reads what the server declares. What a page actually loads, what a script on " +
				"it does, and whether a declared policy is enforced in practice are visible only to a " +
				"browser executing the page, and no browser executed anything here.",
		},
		{
			ID:    "web-one-moment",
			Title: "One answer, from one machine, at one moment",
			Text: "A name served by several machines, or one running an experiment, can answer the " +
				"next visitor differently. This is what one address said once.",
		},
	}
}

// landed returns the last hop that answered, or nil if none did.
func landed(chain []WebHop) *WebHop {
	for i := len(chain) - 1; i >= 0; i-- {
		if chain[i].Answered {
			return &chain[i]
		}
	}
	return nil
}

// firstAnswer returns the first hop that answered, or nil.
func firstAnswer(chain []WebHop) *WebHop {
	for i := range chain {
		if chain[i].Answered {
			return &chain[i]
		}
	}
	return nil
}

// viaPlaintext reports whether a chain made more than one cleartext request
// before reaching TLS.
//
// The first hop is the one the visitor made; every cleartext hop after it is
// one this site sent them to, and each is another request an attacker on the
// path can answer instead.
func viaPlaintext(chain []WebHop) bool {
	seen := 0
	for _, h := range chain {
		if h.TLS {
			break
		}
		if h.Answered {
			seen++
		}
	}
	return seen > 1
}

func redirectStatus(status int) bool { return status >= 300 && status < 400 }

// temporary reports whether a redirect status tells a browser not to remember
// it. 301 and 308 are permanent; 302, 303 and 307 are not.
func temporary(status int) bool {
	switch status {
	case 302, 303, 307:
		return true
	}
	return false
}

// humanAge renders a max-age as something a reader can weigh.
//
// A report saying "31536000" asks its reader to divide. The rules never read
// this string, so its only job is to be understood.
func humanAge(seconds int64) string {
	switch {
	case seconds >= 63072000:
		return fmt.Sprintf("%d years", seconds/31536000)
	case seconds >= 31536000:
		return "a year"
	case seconds >= 172800:
		return fmt.Sprintf("%d days", seconds/86400)
	case seconds >= 86400:
		return "a day"
	case seconds >= 7200:
		return fmt.Sprintf("%d hours", seconds/3600)
	case seconds >= 60:
		return fmt.Sprintf("%d minutes", seconds/60)
	}
	return fmt.Sprintf("%d seconds", seconds)
}
