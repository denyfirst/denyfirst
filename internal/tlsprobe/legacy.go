package tlsprobe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/rawhello"
	"github.com/denyfirst/porch/internal/safedial"
)

// Legacy is what hand-written hellos established about the things Go's own
// client cannot offer.
//
// Six questions, each one connection: does the server speak SSL 3.0, does it
// accept an export-grade suite, a NULL suite, a finite-field DHE suite or an
// anonymous suite, and does it refuse a downgraded hello carrying
// TLS_FALLBACK_SCSV. None completes a handshake; see internal/rawhello for
// exactly what is sent and read.
type Legacy struct {
	// Asked is false when none of the ordinary handshakes was answered, so none
	// of these was put. Renderers show nothing for a question nobody asked.
	Asked bool `json:"asked"`

	SSL3   LegacyAnswer `json:"ssl3"`
	Export LegacyAnswer `json:"export"`
	Null   LegacyAnswer `json:"null"`

	// FFDHE and Anonymous are the two families Go's client implements no
	// suite of at all, so the ordinary enumeration could never list one.
	FFDHE     LegacyAnswer `json:"ffdhe"`
	Anonymous LegacyAnswer `json:"anonymous"`

	Fallback Fallback `json:"fallback"`
}

// LegacyAnswer is one of those questions.
//
// Three states and never two. Accepted and refused are both measurements; a
// question with neither is not a refusal, because a closed connection is what a
// server that refuses looks like and also what a firewall looks like (R4).
type LegacyAnswer struct {
	Measured bool `json:"measured"`
	Accepted bool `json:"accepted"`
	Refused  bool `json:"refused"`

	// Version is the version the server chose, when it accepted.
	Version string `json:"version,omitempty"`

	// VersionGrade is set when the version chosen was SSL 3.0, which is graded
	// on its own. Carried here rather than recomputed by each renderer, so the
	// terminal and the page read the grade from the same place (R16).
	VersionGrade *policy.VersionFinding `json:"versionGrade,omitempty"`

	// Suite is the suite the server chose, graded, when it accepted.
	Suite *CipherResult `json:"suite,omitempty"`

	// Reason says why nothing was measured.
	Reason string `json:"reason,omitempty"`
}

// Fallback is what a downgraded hello carrying TLS_FALLBACK_SCSV was answered
// with.
//
// Reported and never graded. RFC 7507 tells a server that speaks something newer
// to refuse such a hello, and a server that does not leaves a client that
// retries at an older version open to being held there. What that costs depends
// on the version it lands on — and that version is graded on its own already.
type Fallback struct {
	Measured bool `json:"measured"`
	Honoured bool `json:"honoured"`

	// Asked names the version the downgraded hello claimed.
	Asked string `json:"asked,omitempty"`

	Reason string `json:"reason,omitempty"`
}

const notAskedNothingAnswered = "not asked: none of the ordinary handshakes was answered, so there was nothing to ask"

// legacy puts the four questions.
//
// Only where something answered an ordinary handshake — accepted or refused. A
// name that did not resolve, a destination safedial refused, a host that timed
// out on every version: in each, four more connections would learn nothing and
// would add four attempts to a counter an operator reads.
func (p *Prober) legacy(ctx context.Context, host, port string, results []VersionResult, reached *addressSet) Legacy {
	if !suiteCoverageApplies(results) {
		return Legacy{
			SSL3:      LegacyAnswer{Reason: notAskedNothingAnswered},
			Export:    LegacyAnswer{Reason: notAskedNothingAnswered},
			Null:      LegacyAnswer{Reason: notAskedNothingAnswered},
			FFDHE:     LegacyAnswer{Reason: notAskedNothingAnswered},
			Anonymous: LegacyAnswer{Reason: notAskedNothingAnswered},
			Fallback:  Fallback{Reason: notAskedNothingAnswered},
		}
	}

	out := Legacy{Asked: true}

	var wg sync.WaitGroup
	wg.Add(5)
	go func() {
		defer wg.Done()
		out.FFDHE = p.askLegacy(ctx, host, port, modernHello(host, rawhello.FFDHE), rawhello.FFDHE, reached)
	}()
	go func() {
		defer wg.Done()
		out.Anonymous = p.askLegacy(ctx, host, port, modernHello(host, rawhello.Anonymous), rawhello.Anonymous, reached)
	}()
	go func() {
		defer wg.Done()
		out.SSL3 = p.askLegacy(ctx, host, port, rawhello.Hello{
			RecordVersion: policy.VersionSSL30,
			ClientVersion: policy.VersionSSL30,
			Suites:        rawhello.IDs(rawhello.SSL3),
		}, rawhello.SSL3, reached)
	}()
	go func() {
		defer wg.Done()
		out.Export = p.askLegacy(ctx, host, port, modernHello(host, rawhello.Export), rawhello.Export, reached)
	}()
	go func() {
		defer wg.Done()
		out.Null = p.askLegacy(ctx, host, port, modernHello(host, rawhello.Null), rawhello.Null, reached)
	}()
	wg.Wait()

	out.Fallback = p.fallback(ctx, host, port, results, reached)
	return out
}

// modernHello claims TLS 1.2 and offers only the suites given.
//
// Only those. A hello that also offered sound suites would be answered with one
// of them by any server with a preference, and the question — would it accept
// this at all — would go unasked.
func modernHello(host string, suites []rawhello.Suite) rawhello.Hello {
	return rawhello.Hello{
		RecordVersion: policy.VersionTLS10,
		ClientVersion: policy.VersionTLS12,
		Suites:        rawhello.IDs(suites),
		Extensions:    true,
		ServerName:    host,
	}
}

// askLegacy sends one hello and reduces the answer.
func (p *Prober) askLegacy(ctx context.Context, host, port string, hello rawhello.Hello, offered []rawhello.Suite, reached *addressSet) LegacyAnswer {
	got := p.rawAsk(ctx, host, port, hello, reached)

	switch got.Answer {
	case rawhello.Refused:
		return LegacyAnswer{Measured: true, Refused: true}

	case rawhello.Accepted:
		// A server may only choose from what it was offered, at a version no
		// higher than the hello claimed. One that does otherwise is not
		// speaking the protocol, and reading a suite out of its reply would be
		// believing a server about the one thing it has just shown it gets
		// wrong.
		offeredSuite := slices.ContainsFunc(offered, func(s rawhello.Suite) bool { return s.ID == got.Suite })
		if !offeredSuite || got.Version > hello.ClientVersion || got.Version < policy.VersionSSL30 {
			return LegacyAnswer{Reason: "the server answered with a version or a suite it was not offered, so nothing was read from it"}
		}

		suite := CipherResult{ID: got.Suite, CipherFinding: policy.GradeCipher(rawhello.Name(got.Suite))}
		out := LegacyAnswer{
			Measured: true,
			Accepted: true,
			Version:  versionName(got.Version),
			Suite:    &suite,
		}
		if got.Version == policy.VersionSSL30 {
			grade := policy.GradeVersion(policy.VersionSSL30)
			out.VersionGrade = &grade
		}
		return out

	default:
		return LegacyAnswer{Reason: legacyReason(got.Err)}
	}
}

// fallback asks whether a downgraded hello is refused.
//
// The hello claims the newest version the server accepted below its newest, and
// carries the signal. RFC 7507: a server whose highest version is higher than
// the hello claims must answer with inappropriate_fallback. A server accepting
// only one version has nowhere for a client to be pushed down to, and is not
// asked.
func (p *Prober) fallback(ctx context.Context, host, port string, results []VersionResult, reached *addressSet) Fallback {
	var accepted []uint16
	for _, v := range results {
		if v.Supported {
			accepted = append(accepted, v.Version)
		}
	}
	slices.Sort(accepted)

	if len(accepted) < 2 {
		return Fallback{Reason: "not asked: the server accepts only one version, so there is no older one for a client to be pushed down to"}
	}

	below := accepted[len(accepted)-2]
	hello := rawhello.Hello{
		RecordVersion: policy.VersionTLS10,
		ClientVersion: below,
		Suites:        append(candidateSuites(below), rawhello.FallbackSCSV),
		Extensions:    true,
		ServerName:    host,
	}

	out := Fallback{Asked: versionName(below)}
	got := p.rawAsk(ctx, host, port, hello, reached)

	switch {
	case got.Answer == rawhello.Refused && got.Alert == rawhello.AlertInappropriateFallback:
		out.Measured, out.Honoured = true, true
	case got.Answer == rawhello.Refused:
		// Refused, and not for the signal. The server may have declined the
		// suites or the version for its own reasons, and that says nothing about
		// whether it recognises the signal.
		out.Reason = "the downgraded hello was refused for a reason other than the signal, so whether the server recognises it was not established"
	case got.Answer == rawhello.Accepted && got.Version == below:
		out.Measured = true
	case got.Answer == rawhello.Accepted:
		out.Reason = "the downgraded hello was answered with a version it did not claim, so nothing was read from it"
	default:
		out.Reason = legacyReason(got.Err)
	}
	return out
}

// rawAsk dials exactly as a handshake does and sends one hello.
//
// Through p.dial(), which is safedial unless a caller replaced it, so the guard
// on where these four connections go is the guard on every other connection in
// a scan. A second dialler here would be a second place to forget it (N6).
func (p *Prober) rawAsk(ctx context.Context, host, port string, hello rawhello.Hello, reached *addressSet) rawhello.Result {
	ctx, cancel := context.WithTimeout(ctx, p.handshakeTimeout())
	defer cancel()

	conn, err := p.dial()(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return rawhello.Result{Answer: rawhello.Unanswered, Err: err}
	}
	defer conn.Close()

	if remote := conn.RemoteAddr(); remote != nil {
		reached.add(remote.String())
	}
	return rawhello.Ask(ctx, conn, hello)
}

// legacyReason turns a failure into a phrase safe to publish.
//
// Fixed phrases only, for the reason classifyHandshakeError gives: Go's errors
// name resolvers and addresses, and none of that belongs in a report (I6).
func legacyReason(err error) string {
	var netErr net.Error
	switch {
	case err == nil:
		return "the question could not be put"
	case errors.Is(err, safedial.ErrBlocked):
		return "not asked: this is not a destination the service will connect to"
	case errors.Is(err, rawhello.ErrNotTLS):
		return "the server answered with something that is not TLS"
	case errors.Is(err, rawhello.ErrNotServerHello), errors.Is(err, rawhello.ErrSplit):
		return "the reply could not be read as a server hello, so nothing was taken from it"
	case errors.Is(err, context.Canceled):
		return "the scan was cancelled before this was asked"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "the server did not answer in time"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.ErrClosedPipe),
		strings.Contains(err.Error(), "connection reset"), strings.Contains(err.Error(), "closed"):
		return "the server closed the connection without an answer, which many servers do instead of refusing, so it is not counted as a refusal"
	default:
		return "the question could not be put"
	}
}

// mergeLegacy folds what the hand-written hellos found into the verdict.
//
// Only upwards. A suite accepted here can make a report worse and never better:
// the ordinary handshakes may have returned Ungraded because a suite list was
// cut short (see summarise), and policy.Worst ignores Ungraded — so a strong
// verdict from here would silently turn "no verdict was reached" into "strong".
// Nothing these hellos can accept grades strong today; the guard is for the day
// a list changes.
func mergeLegacy(verdict policy.Verdict, findings []policy.Finding, l Legacy) (policy.Verdict, []policy.Finding) {
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.RuleID] = true
	}

	raise := func(v policy.Verdict, fs []policy.Finding) {
		if v.Rank() > 0 {
			verdict = policy.Worst(verdict, v)
		}
		for _, f := range fs {
			if !seen[f.RuleID] {
				seen[f.RuleID] = true
				findings = append(findings, f)
			}
		}
	}

	for _, a := range []LegacyAnswer{l.SSL3, l.Export, l.Null, l.FFDHE, l.Anonymous} {
		if !a.Accepted {
			continue
		}
		if a.VersionGrade != nil {
			raise(a.VersionGrade.Verdict, a.VersionGrade.Findings)
		}
		if a.Suite != nil {
			raise(a.Suite.Verdict, a.Suite.Findings)
		}
	}

	slices.SortStableFunc(findings, func(a, b policy.Finding) int {
		return b.Verdict.Rank() - a.Verdict.Rank()
	})
	return verdict, findings
}

// describeLegacy says what the hand-written hellos could not establish, and what
// the downgraded one was answered with.
func (r *Report) describeLegacy() {
	l := r.Legacy
	if !l.Asked {
		return
	}

	var unmeasured []string
	for _, q := range []struct {
		name   string
		answer LegacyAnswer
	}{
		{"SSL 3.0", l.SSL3},
		{"an export-grade suite", l.Export},
		{"a NULL suite", l.Null},
		{"a finite-field DHE suite", l.FFDHE},
		{"an anonymous suite", l.Anonymous},
	} {
		if !q.answer.Measured {
			unmeasured = append(unmeasured, q.name)
		}
	}
	if len(unmeasured) > 0 {
		// Unsettled, because the reassuring reading is the one a reader
		// supplies for a gap: nothing reported accepted reads as nothing
		// accepted (R4).
		r.unsettled("Whether the server accepts " + listed(unmeasured) + " was not established: the " +
			"hand-written hello asking about it got no answer that could be read. That is not a refusal — " +
			"a server that closes the connection instead of refusing looks exactly like this.")
	}

	f := l.Fallback
	switch {
	case f.Measured && f.Honoured:
		r.observe(fmt.Sprintf("A hello claiming only %s and carrying TLS_FALLBACK_SCSV was refused with the "+
			"alert RFC 7507 defines, so a client pushed down to an older version by an interrupted connection "+
			"is told so rather than kept there.", f.Asked))
	case f.Measured:
		r.observe(fmt.Sprintf("A hello claiming only %s and carrying TLS_FALLBACK_SCSV was answered with a "+
			"handshake. RFC 7507 asks a server that speaks something newer to refuse it, so a client that "+
			"retries at an older version after a failed connection can be held there by whoever broke the "+
			"first attempt. Reported rather than graded: what a downgrade costs depends on the version it "+
			"lands on, and that version is graded above on its own.", f.Asked))
	}
}

// listed writes "a, b and c".
func listed(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
	}
}
