// Package webscan measures how a name is reached over HTTP and grades it.
//
// It is the joint between two packages that deliberately do not know about
// each other: internal/webprobe opens the connections and records what came
// back, internal/policy holds the rules and imports nothing of this project's
// own. Everything here is the translation between them, and the translation
// is where the interesting mistakes are.
//
// The one that matters most is which response's policy counts. A browser
// applies Strict-Transport-Security from every response it receives over a
// secure transport and ignores it on every response that arrives any other
// way, so a chain of three redirects has three chances to set a policy and
// one of them may be the only one that does. Reading the header off the last
// hop, or off the first, both describe a policy no browser holds.
package webscan

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/exclusion"
	"github.com/denyfirst/denyfirst/internal/markup"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/verify"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// hstsHeader is the header the rules read. Spelled once.
const hstsHeader = "Strict-Transport-Security"

// Scanner measures one host. The zero value is usable.
type Scanner struct {
	// Prober opens the connections. Nil means a default one, which refuses
	// private addresses and every port but 80 and 443.
	Prober *webprobe.Prober

	// Verify is the proof of control this deployment requires before it will
	// scan a name. Nil means none is required, which is what the command line
	// wants and what a service must not have.
	Verify *verify.Scope

	// Roots is the trust store every certificate on a chain is judged against.
	//
	// Nil means the system store, loaded explicitly rather than left for
	// crypto/tls to interpret — see webprobe.Prober.Roots for what nil means
	// there and why it is not this. Carried on the Scanner rather than only on
	// the Prober so that a caller configuring the check has one place to say
	// it, and so a service that resolved its own store can hand over the store
	// it resolved.
	Roots *x509.CertPool

	// ReadMarkup asks for the page to be read, not only its headers.
	//
	// False by default, which is the behaviour this check had for its whole
	// life and the safe thing for an unset field to mean. What a true here buys
	// is the things a header cannot show: a Content-Security-Policy declared
	// with <meta http-equiv>, which a browser applies and a header check
	// reported as absent.
	//
	// Nothing of the page is kept. What comes back is internal/markup.Facts —
	// hosts and booleans — and there is no field between here and a report that
	// could hold markup. That is the condition reading a body was allowed on at
	// all, and docs/scope.md has the argument.
	//
	// A demonstration build ignores this. The refusal is in webprobe, at the
	// response, so it holds for every path rather than for the ones that
	// remembered.
	ReadMarkup bool

	// Now supplies the current time, so a duration is reproducible in tests.
	// Nil means time.Now.
	Now func() time.Time
}

// Result is one host, measured and graded.
type Result struct {
	Host string `json:"host"`

	// Policy names the rule set behind every verdict here, so a result can be
	// reproduced after the rules move on. It is never the TLS rule set: these
	// are different questions over different evidence, and a report that
	// carried one name for both would make two incomparable things look
	// comparable.
	Policy string `json:"policy"`

	// Verdict is the worst of everything below. Empty means nothing was
	// graded, which is not the same as nothing being wrong.
	Verdict policy.Verdict `json:"verdict,omitempty"`

	Findings []policy.Finding `json:"findings,omitempty"`

	// Notes carry their kind: what was observed, what could not be settled,
	// and what is true of every scan this program runs.
	Notes []policy.Note `json:"notes,omitempty"`

	// Observed is what the probe saw, kept so that a reader can check a
	// verdict against the evidence rather than taking it on trust.
	Observed *webprobe.Report `json:"observed,omitempty"`

	Duration time.Duration `json:"duration"`
}

// Scan measures one host and grades what it finds.
//
// An error means the target was refused before anything was attempted. A host
// that does not answer is not an error: it is a result with notes saying what
// could not be established, which is a different thing and is reported as one.
func (s *Scanner) Scan(ctx context.Context, host string) (*Result, error) {
	started := s.now()

	// Valid first, and only then permitted. Asked the other way round, a
	// demonstration build answers "this deployment does not demonstrate that"
	// to somebody who simply mistyped, which tells them the wrong thing about
	// their own mistake. The probe defines what a target is, so the probe is
	// what is asked.
	if err := webprobe.CheckHostname(host); err != nil {
		return nil, err
	}

	// A short list of names this project will not scan, whoever asks and
	// whichever check they ask for (N8).
	//
	// The TLS scanner has asked it since the list existed; this one did not,
	// so until 2026-09-10 a name was refused by one check and scanned by the
	// other. The list was in internal/scan, and reaching it from here would
	// have meant importing the TLS scanner to find out what this check may
	// connect to — so it moved to internal/exclusion, exactly as the
	// demonstration list moved to internal/demo on 2026-09-05, and for the
	// same reason.
	//
	// Asked here rather than in the HTTP handler, so it holds for the command
	// line and for anything written later.
	if exclusion.Covers(host) {
		return nil, exclusion.ErrRefused
	}

	// This deployment connects only to hosts this project owns (N6).
	//
	// Here, where the scan is decided, and not in whatever calls it. A guard
	// in one place is a guard somebody walks around by adding an entry point,
	// and this check exists before the entry point that will need it: the
	// HTTP service has no web address yet. When it gets one it inherits this
	// rather than repeating it.
	//
	// The list is the same list the TLS scanner asks, from the same package
	// and under the same build tag. Two checks reaching two lists is how a
	// deployment ends up demonstrating one thing and connecting to another.
	if demo.Refusal(host) {
		return nil, demo.ErrNotATarget
	}

	// And the third source of authority. Same place, same reason as the two
	// above: a deployment that requires proof of control scans only what it
	// has been shown, and a guard in one entry point disappears the moment a
	// second is added.
	if s.Verify != nil {
		if err := s.Verify.Covers(ctx, host, verify.HTTPOnly); err != nil {
			return nil, err
		}
	}

	prober := s.Prober
	if prober == nil {
		prober = &webprobe.Prober{}
	}

	// A copy, so that configuring the store does not reach into a Prober the
	// caller owns and may be using elsewhere. Prober holds values and functions
	// and no lock, and vet's copylocks check fails if that stops being true.
	//
	// Carried over rather than replaced, for the reason UseWebScanner carries a
	// boundary over: a caller that set a store on the prober has said something,
	// and a scanner that overwrote it would widen or narrow what decides
	// "trusted" without anybody asking.
	p := *prober
	if p.Roots == nil {
		p.Roots = s.Roots
	}

	// Whether the page itself is read, decided here with the three guards
	// above rather than by whoever built the Prober.
	//
	// The same offer-by-deployment shape the log search uses, and the reasoning
	// differs from it in one way worth writing down. The log search is a switch
	// on the command line because the question names a domain that may be
	// somebody else's, and asking it discloses to a third party that somebody
	// is looking. Reading a page discloses nothing to anybody: it is one more
	// GET of an address this scan has already fetched the headers of, and the
	// server served the same bytes to every visitor it had today. So there is
	// no switch to offer and none is offered.
	//
	// What decides it instead is what a report may carry. On the command line
	// the report goes to the person who ran it, on their own machine. On a
	// deployment that required proof of control the page belongs to whoever
	// asked. A demonstration build reads no body at all, and that is enforced
	// in webprobe rather than here, so the promise on /web/method holds for
	// every path into the prober rather than for this one.
	p.ReadMarkup = s.ReadMarkup
	prober = &p

	// And again, for every host a redirect names.
	//
	// The three guards above authorise the host that was asked about. A
	// redirect is a different host, chosen by the server that answered rather
	// than by the operator, and until this was passed the probe followed one
	// anywhere the ports and safedial allowed. So a name on the exclusion
	// list was refused when typed and reached when a redirect pointed at it;
	// so was a host outside a demonstration build; and a deployment that
	// scans only what it has been shown control of could be walked out of its
	// own estate by one Location header on a site it does own.
	//
	// N10 has the reasoning. The same three sources of authority, in the same
	// order, are what s.reachable asks.
	observed, err := prober.Probe(ctx, host, s.reachable)
	if err != nil {
		return nil, err
	}

	out := Grade(observed)
	out.Host = host
	out.Duration = s.now().Sub(started)
	return out, nil
}

// reachable answers whether a redirect may be followed to a host, and why not
// when it may not.
//
// It asks what Scan asks about the host it was given, in the same order and
// from the same three sources of authority, because a redirect target is a
// host this deployment is about to connect to and there is no second set of
// rules about that. Written once here rather than twice, so that a source of
// authority added later cannot hold at the front door and not at the hop.
//
// The sentences are fixed and none of them repeats the name (I3). They go into
// a report, and the report goes to whoever asked — including, on a service, a
// stranger. The Location header is kept in the hop that produced it, so a
// reader can see the address without this saying it.
func (s *Scanner) reachable(ctx context.Context, host string) string {
	if exclusion.Covers(host) {
		return "the Location header named a domain this service does not scan"
	}

	if demo.Refusal(host) {
		return "the Location header named a host outside what this deployment scans"
	}

	if s.Verify == nil {
		return ""
	}

	// HTTPOnly, the same surface Scan asks for, because a redirect hop is the
	// same kind of connection as the first one: ports 80 and 443, read the way
	// a browser reads them. So a host that proved control by serving the
	// challenge file proves enough for a hop as well — the file proof is
	// narrow because it says nothing about a zone or about a port a browser
	// never opens, and neither of those is what a redirect asks for.
	//
	// It has a cost, and it is written here rather than left to be discovered.
	// Asking this way means a deployment with a Fetcher configured makes one
	// request to the redirect target before refusing it: a GET of the
	// challenge path, over 443, identifying itself, no redirect followed and
	// a capped body. So "nothing is dialled" is true of the probe and not
	// literally true of the machine.
	//
	// The alternative is to accept only the zone proof at a hop, which costs
	// one lookup and no connection. It was not taken, because the file proof
	// exists for teams with no DNS access, and apex-to-www is the redirect
	// almost every site has: those teams would get a chain truncated at the
	// first hop with nothing they could do about it. What is spent instead is
	// one fixed, published request — strictly less than the probe that used to
	// happen there unasked, and less than the check itself does to any host it
	// is pointed at.
	if err := s.Verify.Covers(ctx, host, verify.HTTPOnly); err != nil {
		if errors.Is(err, verify.ErrNotVerified) {
			return "the Location header named a domain this deployment has not been shown control of"
		}

		// Any other failure is this deployment being unable to ask rather
		// than an answer, and it stops the chain. Following on would be a
		// boundary that opens whenever a resolver is slow, which is a
		// boundary somebody can arrange to be slow.
		return "whether that domain may be reached could not be established"
	}

	return ""
}

// Grade turns what a probe observed into a graded result.
//
// Separate from Scan, and exported, for one reason: without it a test with no
// network reimplements these few lines, and a reimplementation keeps passing
// after the original stops doing what it copied. There is one copy of the
// order the checks run in, the way their verdicts combine, and the fact that
// the limits of the method are attached last.
func Grade(observed *webprobe.Report) *Result {
	out := &Result{
		Host:     observed.Host,
		Policy:   policy.WebVersion,
		Observed: observed,
	}

	reach := policy.GradeReach(hops(observed.Secure), hops(observed.Plain))
	hsts := policy.GradeHSTS(securePolicy(observed.Secure), plaintextPolicy(observed.Plain),
		answered(observed.Secure))
	cookies := policy.GradeCookies(cookieFacts(observed))
	headers := policy.GradeHeaders(headerFacts(observed.Secure))
	content := policy.GradeContent(contentFacts(observed.Secure))

	// Worst case across the checks, for the reason it is worst case within
	// one: a site reached in the clear is reached in the clear however sound
	// its policy declaration is.
	for _, r := range []policy.WebResult{reach, hsts, cookies, headers, content} {
		out.Findings = append(out.Findings, r.Findings...)
		out.Notes = append(out.Notes, r.Notes...)
		out.Verdict = policy.Worst(out.Verdict, r.Verdict)
	}

	// A store that could not be read, said before the standing limits because
	// it qualifies this report rather than describing every report.
	//
	// Without it a reader is handed a site reported as not served over HTTPS,
	// with no way to tell that from the truth: every handshake failed because
	// nothing on this machine could say what a trusted root is. A fact about
	// the machine running the scan printed as a finding about somebody else's
	// server is the failure R4 exists for.
	if observed.TrustStoreUnreadable {
		out.Notes = append(out.Notes, policy.TrustStoreUnreadable())
	}

	// The limits of the method, last, and from the one place that declares
	// them. A report that wrote its own would drift from the page explaining
	// them, and the sentence a reader is asked to trust would then exist in
	// two versions.
	for _, l := range policy.WebStandingLimits() {
		out.Notes = append(out.Notes, l.Note())
	}

	return out
}

// hops reduces a chain to what the rules read.
//
// The rules are given a status and two booleans rather than the chain itself,
// so that internal/policy keeps its one unusual property: it imports nothing
// of this project's own, and a rule can be read without reading a probe.
func hops(c *webprobe.Chain) []policy.WebHop {
	if c == nil {
		return nil
	}
	out := make([]policy.WebHop, 0, len(c.Hops))
	for _, h := range c.Hops {
		out = append(out, policy.WebHop{
			TLS:      h.TLS,
			Answered: h.Err == "",
			Status:   h.Status,
		})
	}
	return out
}

// securePolicy returns the Strict-Transport-Security a browser would end up
// holding after following this chain.
//
// A browser applies the header from every response that arrives over a secure
// transport, so the value it keeps is the last one it was given that way. Not
// the last hop, which may be plaintext where a site downgrades, and not the
// first, which a later hop may have replaced. Both of those describe a policy
// no browser holds.
//
// A hop that failed carries no headers and is skipped rather than treated as
// a response with none: a connection that was refused says nothing about what
// the server declares.
func securePolicy(c *webprobe.Chain) []string {
	if c == nil {
		return nil
	}
	for i := len(c.Hops) - 1; i >= 0; i-- {
		h := c.Hops[i]
		if !h.TLS || h.Err != "" {
			continue
		}
		if v := h.Headers[hstsHeader]; len(v) > 0 {
			return v
		}
	}
	return nil
}

// plaintextPolicy returns a Strict-Transport-Security sent where a browser
// will ignore it.
//
// Read so that the rules can tell "no policy" from "a policy declared only
// where RFC 6797 requires a browser to discard it", which is a common
// arrangement and one nothing else in a report would show. The first such hop
// is enough: the question is whether it happens at all, not which value.
func plaintextPolicy(c *webprobe.Chain) []string {
	if c == nil {
		return nil
	}
	for _, h := range c.Hops {
		if h.TLS || h.Err != "" {
			continue
		}
		if v := h.Headers[hstsHeader]; len(v) > 0 {
			return v
		}
	}
	return nil
}

// answered reports whether any hop in a chain produced a response.
//
// No list of headers can carry the difference between a host that answered
// without a header and a host that answered nothing: both are empty. The
// rules are told which it was, because grading the second as "declares no
// policy" is a claim about a server nothing here ever spoke to.
func answered(c *webprobe.Chain) bool {
	if c == nil {
		return false
	}
	for _, h := range c.Hops {
		if h.Err == "" {
			return true
		}
	}
	return false
}

func (s *Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// cookieFacts reduces every cookie in both chains to what the rules read.
//
// Both chains, because a cookie set anywhere along the way is a cookie the
// visitor carries. A hop that failed carries none, and is skipped rather than
// treated as a response that set nothing.
//
// Each cookie is tagged with whether the response that set it arrived over
// TLS, which is the fact that decides what a missing Secure attribute means: a
// cookie set on a plaintext response was already in the clear before any
// attribute could have helped, and that is the reach finding rather than a
// cookie one. Charging it twice would report one mistake as two.
func cookieFacts(r *webprobe.Report) []policy.CookieFacts {
	var out []policy.CookieFacts

	for _, c := range []*webprobe.Chain{r.Secure, r.Plain} {
		if c == nil {
			continue
		}
		for _, hop := range c.Hops {
			if hop.Err != "" {
				continue
			}
			for _, cookie := range hop.Cookies {
				out = append(out, policy.CookieFacts{
					Name:         cookie.Name,
					Secure:       cookie.Secure,
					HTTPOnly:     cookie.HTTPOnly,
					SameSite:     cookie.SameSite,
					Path:         cookie.Path,
					DomainSet:    cookie.DomainSet,
					HostPrefix:   cookie.HostPrefix,
					SecurePrefix: cookie.SecurePrefix,
					OverTLS:      hop.TLS,
				})
			}
		}
	}

	return out
}

// headerFacts reduces the response a visitor lands on to what the rules read.
//
// The last hop of the secure chain that produced a response, which is a
// different choice from the one securePolicy makes and the difference matters.
// Strict-Transport-Security persists in the browser, so the value that counts
// is the last one carried by any hop made over TLS. These headers apply to the
// response that carries them and to nothing else, so the one that counts is
// the response whose content the visitor actually receives.
//
// A hop that failed carries no headers and is skipped rather than treated as a
// response with none.
func headerFacts(c *webprobe.Chain) policy.HeaderFacts {
	var out policy.HeaderFacts
	if c == nil {
		return out
	}

	for i := len(c.Hops) - 1; i >= 0; i-- {
		h := c.Hops[i]
		if !h.TLS || h.Err != "" {
			continue
		}

		out.Answered = true
		out.Present = make(map[string]bool, len(h.Headers))
		for name, values := range h.Headers {
			if len(values) > 0 {
				out.Present[name] = true
			}
		}
		out.ACAO = first(h.Headers["Access-Control-Allow-Origin"])
		out.ACAC = first(h.Headers["Access-Control-Allow-Credentials"])

		// The markup of the same response, not of some other hop. A policy
		// declared in a page applies to that page, so reading one response's
		// headers beside another's markup would be assembling a site that does
		// not exist out of two that do.
		if h.Markup != nil {
			out.MarkupRead = h.Markup.Read
			out.MetaCSP = h.Markup.MetaCSP
			out.MetaCSPReportOnly = h.Markup.MetaCSPReportOnly
		}
		return out
	}

	return out
}

// first returns the first value of a header, or empty.
//
// A browser processes the first of a repeated header for the ones read here,
// so reading any other would describe something no client acts on.
func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// contentFacts reduces the markup of the response a visitor lands on to what
// the content rules read.
//
// The same hop headerFacts reads, and it has to be: a policy declared in a page
// applies to that page, and what a page loads is a fact about that page.
// Reading one response's headers beside another's markup would assemble a site
// that does not exist out of two that do.
//
// The secure chain only. Mixed content is a question about a page served over
// TLS — on a plaintext page everything is plaintext, and reporting it would be
// telling somebody their http page loads things over http.
func contentFacts(c *webprobe.Chain) policy.ContentFacts {
	var out policy.ContentFacts
	if c == nil {
		return out
	}

	for i := len(c.Hops) - 1; i >= 0; i-- {
		h := c.Hops[i]
		if !h.TLS || h.Err != "" {
			continue
		}
		if h.Markup == nil {
			return out
		}

		out.Read = h.Markup.Read
		out.Truncated = h.Markup.Truncated
		out.MoreThanListed = h.Markup.MoreThanListed

		for _, r := range h.Markup.References {
			// Plaintext first, in every case. A form posting to another origin
			// over plaintext is the plaintext finding, not the off-origin
			// sentence, and a script from elsewhere over plaintext is one a
			// browser refuses outright — so integrity is beside the point.
			// Sorting the other way would answer the smaller question and
			// leave the larger one unsaid.
			switch {
			case r.Kind == markup.KindForm && r.Plaintext:
				out.Forms = append(out.Forms, r.Host)
			case r.Kind == markup.KindForm:
				out.OffOrigin = append(out.OffOrigin, r.Host)

			case r.Plaintext && r.Blocking:
				out.Blocking = append(out.Blocking, r.Host)
			case r.Plaintext:
				out.Passive = append(out.Passive, r.Host)

			// What is left is over TLS, from another origin. Only the two
			// elements subresource integrity covers are asked about: a frame
			// or an image from elsewhere is not code this page executes, and
			// there is no attribute for a browser to check.
			case r.Kind == markup.KindScript || r.Kind == markup.KindStyle:
				if r.Integrity {
					out.Verified = append(out.Verified, r.Host)
				} else {
					out.Unverified = append(out.Unverified, r.Host)
				}
			}
		}
		return out
	}

	return out
}
