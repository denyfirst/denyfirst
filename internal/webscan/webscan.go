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
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// hstsHeader is the header the rules read. Spelled once.
const hstsHeader = "Strict-Transport-Security"

// Scanner measures one host. The zero value is usable.
type Scanner struct {
	// Prober opens the connections. Nil means a default one, which refuses
	// private addresses and every port but 80 and 443.
	Prober *webprobe.Prober

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

	prober := s.Prober
	if prober == nil {
		prober = &webprobe.Prober{}
	}

	observed, err := prober.Probe(ctx, host)
	if err != nil {
		return nil, err
	}

	out := Grade(observed)
	out.Host = host
	out.Duration = s.now().Sub(started)
	return out, nil
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

	// Worst case across the checks, for the reason it is worst case within
	// one: a site reached in the clear is reached in the clear however sound
	// its policy declaration is.
	for _, r := range []policy.WebResult{reach, hsts} {
		out.Findings = append(out.Findings, r.Findings...)
		out.Notes = append(out.Notes, r.Notes...)
		out.Verdict = policy.Worst(out.Verdict, r.Verdict)
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
