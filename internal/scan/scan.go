// Package scan joins the probe, the certificate analysis, and the policy into
// one operation.
//
// It exists so the command line tool and the HTTP service run the same code.
// Two copies of this sequence would drift, and target parsing in particular is
// a security boundary: the copy nobody is looking at is the one that falls
// behind.
package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/certinfo"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

const (
	// DefaultPort is assumed when the target names no port.
	DefaultPort = "443"

	// maxHostLen is the longest a DNS name may be, from RFC 1035.
	maxHostLen = 253
)

// AllowedPorts are the ports this project will connect to.
//
// The restriction is not about TLS support; it is about not becoming a port
// scanner for hire. A public service that dials any port on any host lets
// anyone probe a third party's network from our address, and the logs of the
// scanned network will name us rather than them.
//
// Only implicit-TLS ports appear here. STARTTLS ports such as 25, 587, 143
// and 110 are deliberately absent: the probe speaks TLS from the first byte,
// so those would fail in a way that reads as a server fault rather than as a
// missing feature.
var AllowedPorts = []string{
	"443",  // HTTPS
	"8443", // HTTPS, alternate
	"465",  // SMTPS
	"636",  // LDAPS
	"990",  // FTPS
	"993",  // IMAPS
	"995",  // POP3S
	"5061", // SIPS
}

// Result is one target, measured and graded.
type Result struct {
	Target string `json:"target"`

	// Policy names the rule set behind every verdict here.
	Policy string `json:"policy"`

	// Verdict is the worse of the transport and certificate verdicts. Empty
	// when nothing could be measured, which is not the same as passing.
	Verdict policy.Verdict `json:"verdict,omitempty"`

	TLS         *tlsprobe.Report `json:"tls,omitempty"`
	Certificate *certinfo.Report `json:"certificate,omitempty"`

	// Stapling grades the status response against what the certificate asked
	// for. It is neither a transport property nor a certificate property: the
	// request is written in the certificate and the answer arrives in the
	// handshake, so it can only be judged once both are in hand. Absent when
	// no handshake completed, because a question about a response nobody
	// could have sent has no answer.
	Stapling *policy.StapleFinding `json:"stapling,omitempty"`
}

// Scanner runs one scan. The zero value is usable, dials through safedial,
// enforces the port allow list, and takes hostnames rather than addresses.
//
// This project does not offer a way to scan a range. Targets are named one at
// a time and there is no flag, file input, or batch mode that would accept a
// list. Somebody can write a loop around the command, and that loop is theirs;
// the difference between a tool that sweeps and a tool that can be called
// repeatedly is a real one, and it is kept on purpose.
type Scanner struct {
	Prober *tlsprobe.Prober

	// AllowAnyPort disables the port allow list.
	//
	// The check lives here rather than only in the HTTP handler so that it
	// survives a second caller. A guard placed where a request arrives
	// protects that one entry point; a guard placed where the connection is
	// made protects every entry point, including the ones not written yet.
	//
	// It is off by default for the same reason safedial refuses private
	// addresses by default: a protection that must be switched on is one that
	// is eventually forgotten.
	//
	// The command line sets it, because a local operator scanning their own
	// network is not the abuse the list guards against. The service never
	// does, and has no configuration option that would let it.
	AllowAnyPort bool

	// AllowIPTargets permits a bare address as a target.
	//
	// Off by default, and the reason is what the connection looks like at the
	// other end. A scan of a hostname carries that name in the client hello,
	// which is what every browser does; a scan of an address carries no name
	// at all, which is what a scanner does. This project spends a good deal
	// of effort being recognisable rather than suspicious, and this is part
	// of it.
	//
	// It also declines to lend one address to working through a range one
	// entry at a time. Rate limits make that slow rather than impossible, but
	// a sweep run from a shared service leaves its operator's name in the logs
	// of everyone swept.
	//
	// Addresses can hold certificates — 1.1.1.1 has one — so this refuses a
	// legitimate if uncommon check. The command line is where that check
	// belongs: it runs on the operator's own machine, from their own address,
	// so whatever they do is theirs rather than laundered through somebody
	// else's service.
	AllowIPTargets bool

	// Now supplies the current time, so certificate arithmetic is
	// reproducible in tests. Nil means time.Now.
	Now func() time.Time
}

// Scan measures one target, given as a bare host or as host:port.
func (s *Scanner) Scan(ctx context.Context, target string) (*Result, error) {
	host, port, err := SplitTarget(target)
	if err != nil {
		return nil, err
	}
	if !s.AllowAnyPort {
		if err := CheckPort(port); err != nil {
			return nil, err
		}
	}
	if !s.AllowIPTargets && IsIPTarget(host) {
		return nil, errors.New("this takes a hostname rather than an address")
	}

	// Checked here rather than in the HTTP handler so that it holds for every
	// caller, including the command line and anything written later. A guard
	// in one entry point disappears the moment a second one is added.
	if IsExcluded(host) {
		return nil, ErrExcluded
	}

	prober := s.Prober
	if prober == nil {
		prober = &tlsprobe.Prober{}
	}

	out := &Result{
		Target: net.JoinHostPort(host, port),
		Policy: policy.Version,
	}

	tlsReport, err := prober.Probe(ctx, host, port)
	if err != nil {
		return nil, fmt.Errorf("probing %s: %w", out.Target, err)
	}
	out.TLS = tlsReport
	out.Verdict = tlsReport.Verdict

	if len(tlsReport.Certificates) > 0 {
		certReport, err := certinfo.Analyse(tlsReport.Certificates, host, s.now())
		if err != nil {
			return nil, fmt.Errorf("analysing the certificate for %s: %w", out.Target, err)
		}
		out.Certificate = certReport
		out.Verdict = policy.Worst(out.Verdict, certReport.Verdict)

		// The join. tlsprobe saw whether a response arrived; certinfo read
		// whether one was demanded and whether one could exist. Grading
		// either half alone produces the two mistakes this rule is written to
		// avoid: marking a server down for not stapling a response no
		// authority publishes, or passing one that ignores its own
		// certificate's instruction to staple.
		stapling := policy.GradeStapling(policy.StapleFacts{
			Stapled:      tlsReport.OCSPStapled,
			MustStaple:   certReport.Revocation.MustStaple,
			HasResponder: certReport.Revocation.ResponderCount > 0,
			HasCRL:       certReport.Revocation.CRLCount > 0,
		})
		out.Stapling = &stapling
		out.Verdict = policy.Worst(out.Verdict, stapling.Verdict)

		// The second join, and the same shape as the first. Timestamps reach a
		// client three ways and this sees two of them, so what the report can
		// say depends on facts held in three different places: the leaf, the
		// handshake, and whether a response was stapled that might carry the
		// rest. The sentence belongs with the certificate, which is what a
		// reader is looking at when the question occurs to them.
		certReport.Notes = append(certReport.Notes,
			policy.DescribeTransparency(policy.TransparencyFacts{
				Embedded:    certReport.Transparency.EmbeddedCount,
				FromLogs:    certReport.Transparency.LogCount,
				InHandshake: tlsReport.SCTCount,
				Stapled:     tlsReport.OCSPStapled,
				Trusted:     certReport.Trusted,
			})...)
	}

	return out, nil
}

func (s *Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Findings collects every distinct finding across the transport and the
// certificate, so a caller can present the problems without walking the tree.
func (r *Result) Findings() []policy.Finding {
	var (
		out  []policy.Finding
		seen = map[string]bool{}
	)

	collect := func(fs []policy.Finding) {
		for _, f := range fs {
			if seen[f.RuleID] {
				continue
			}
			seen[f.RuleID] = true
			out = append(out, f)
		}
	}

	if r.TLS != nil {
		collect(r.TLS.Findings)
	}
	if r.Certificate != nil {
		collect(r.Certificate.Grade.Findings)
	}
	if r.Stapling != nil {
		collect(r.Stapling.Findings)
	}
	return out
}

// Notes collects every note from both stages.
func (r *Result) Notes() []string {
	var out []string
	if r.TLS != nil {
		out = append(out, r.TLS.Notes...)
	}
	if r.Certificate != nil {
		out = append(out, r.Certificate.Notes...)
	}
	if r.Stapling != nil {
		out = append(out, r.Stapling.Notes...)
	}
	return out
}

// SplitTarget normalises a target into a host and a port.
//
// On the command line the input is a typo; over HTTP it is whatever a stranger
// sent. One implementation means the stricter case sets the rules for both.
//
// The result must be stable: splitting a target, rejoining it with
// net.JoinHostPort, and splitting it again has to give the same answer. If it
// did not, a check performed on one form would not describe the form that is
// eventually dialled, which is where parser-mismatch attacks live. Fuzzing
// found five inputs that broke that property in an earlier version of this
// function, all of them because the host was never examined for shape.
func SplitTarget(target string) (host, port string, err error) {
	target = strings.TrimSpace(target)

	// A pasted URL is a likely mistake rather than something worth refusing,
	// so a scheme is stripped and the path with it. Without a scheme there is
	// nothing to parse by, and a slash could mean anything.
	//
	// The distinction matters because the alternative is silent. Truncating
	// "emanat.az/mpay.az/example.com" to "emanat.az" scans a server the
	// person may not have meant, and discards two thirds of what they typed
	// without saying so. The report would name the right host and the person
	// would still be surprised, which is the failure this project objects to
	// in other tools.
	hadScheme := false
	for _, prefix := range []string{"https://", "http://"} {
		if rest, ok := strings.CutPrefix(target, prefix); ok {
			target = rest
			hadScheme = true
		}
	}

	if i := strings.IndexByte(target, '/'); i >= 0 {
		switch {
		case hadScheme:
			// A URL's host is everything before the first slash. Nothing is
			// being guessed at here.
			target = target[:i]
		case target[i+1:] == "":
			// A bare trailing slash discards nothing.
			target = target[:i]
		default:
			return "", "", errors.New("give the hostname on its own, or a full address beginning with https://; " +
				"everything after the slash would be dropped and this will not do that without saying so")
		}
	}

	if target == "" {
		return "", "", errors.New("the target names no host")
	}

	host, port, err = splitHostPort(target)
	if err != nil {
		return "", "", err
	}
	if err := checkHostSyntax(host); err != nil {
		return "", "", err
	}
	if err := checkPortSyntax(port); err != nil {
		return "", "", err
	}
	return host, port, nil
}

// splitHostPort separates a target without consulting net.SplitHostPort.
//
// That function is written for addresses a program produced, and it accepts
// several forms this one must not. "example.com:" parses with an empty port,
// and a bracketed address with no port fails outright, which left the brackets
// attached to the hostname in the earlier version here.
func splitHostPort(target string) (host, port string, err error) {
	// A bracketed IPv6 literal, with or without a port.
	if strings.HasPrefix(target, "[") {
		end := strings.IndexByte(target, ']')
		if end < 0 {
			return "", "", errors.New("the target opens a bracket that is never closed")
		}

		host = target[1:end]
		switch rest := target[end+1:]; {
		case rest == "":
			return host, DefaultPort, nil
		case strings.HasPrefix(rest, ":"):
			return host, rest[1:], nil
		default:
			return "", "", errors.New("the target has characters after the closing bracket")
		}
	}

	switch strings.Count(target, ":") {
	case 0:
		return target, DefaultPort, nil

	case 1:
		i := strings.IndexByte(target, ':')
		return target[:i], target[i+1:], nil

	default:
		// Several colons and no brackets: either a bare IPv6 literal, which
		// has no room for a port, or nonsense. Accepting it only when it
		// really parses keeps a name such as "a:1:2:3" from being dialled.
		if _, err := netip.ParseAddr(target); err != nil {
			return "", "", errors.New("the target has several colons and is not an IPv6 address")
		}
		return target, DefaultPort, nil
	}
}

// checkHostSyntax accepts only what a resolver can be given.
//
// The permitted set is a list of what is allowed rather than a list of what is
// forbidden. A deny list has to anticipate every dangerous character, and the
// brackets that broke the earlier version of this function were exactly the
// ones nobody thought to forbid.
func checkHostSyntax(host string) error {
	switch {
	case host == "":
		return errors.New("the target names no host")
	case len(host) > maxHostLen:
		return fmt.Errorf("the host exceeds %d bytes", maxHostLen)
	case strings.ContainsAny(host, " \t\r\n\x00"):
		// Trimming removed the harmless case. What is left is interior: a
		// newline inside a hostname is where header injection starts, and a
		// NUL byte is how a truncating parser is made to read a name other
		// than the one that was checked.
		return errors.New("the host contains a control character or a space")
	}

	for _, c := range host {
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == ':':
		default:
			// Colons are permitted above only so that an IPv6 literal reaches
			// the check below; anything else here cannot appear in a name the
			// resolver will accept.
			return errors.New("the host contains a character that cannot appear in a hostname; " +
				"an internationalised name must be given in punycode")
		}
	}

	// A colon is legitimate only inside an IPv6 literal.
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return errors.New("the host contains a colon but is not an IPv6 address")
		}
	}

	// An address is a complete answer on its own and needs no dot; "::1" has
	// none. Everything else does, and the reason is not tidiness.
	//
	// A name with no dot is completed by the resolver from its search list.
	// On a machine configured with "search corp.example.com", asking for
	// "intranet" dials intranet.corp.example.com. The report would then name
	// one host while the connection went to another, which is the same
	// mismatch between what was checked and what was dialled that this
	// function exists to prevent.
	//
	// It is also what a person means: example.az and example.com are
	// different companies, and a bare "example" is neither.
	if _, err := netip.ParseAddr(host); err != nil {
		labels := strings.TrimSuffix(host, ".")
		switch {
		case !strings.Contains(labels, "."):
			return errors.New("the host needs a full name with a domain, such as example.com; " +
				"a bare name would be completed by the resolver's search list and could reach a different server")
		case strings.HasPrefix(labels, "."), strings.Contains(labels, ".."):
			return errors.New("the host has an empty label")
		}
	}

	return nil
}

// checkPortSyntax requires a port in canonical form.
//
// This is separate from CheckPort, which decides whether a well-formed port is
// one this project will dial. Syntax first: net.SplitHostPort does not require
// a port to be numeric, so without this an arbitrary string reaches the allow
// list and, from there, any message built from it.
//
// Canonical means the digits and nothing else. strconv.Atoi accepts "+443" and
// "0443" and reports 443 for both, which would leave three spellings of one
// port in circulation. The allow list compares strings, so those spellings are
// refused today; the reason to reject them here is that the comparison might
// one day become numeric, and then they would quietly be allowed. Two ways to
// write the same value is where parser-mismatch bugs begin.
func checkPortSyntax(port string) error {
	if port == "" {
		return errors.New("the target names no port")
	}

	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("the port must be a number between 1 and 65535")
	}
	if strconv.Itoa(n) != port {
		return errors.New("the port must be written as digits only, without a sign or leading zeros")
	}
	return nil
}

// CheckPort reports whether a well-formed port is one this project will dial.
//
// The error names the port, which is safe for an operator reading a terminal.
// Callers exposed to strangers should still write their own message rather
// than pass this one through, so that nothing a caller sent is reflected back.
func CheckPort(port string) error {
	for _, allowed := range AllowedPorts {
		if port == allowed {
			return nil
		}
	}
	return fmt.Errorf("port %s is not scannable; this project connects only to %s",
		port, strings.Join(AllowedPorts, ", "))
}

// IsIPTarget reports whether a host is a literal address rather than a name.
//
// SplitTarget has already removed any brackets, so an IPv6 literal arrives
// here bare. A name that merely resembles an address — 1.2.3.4.nip.io, or
// 93.184.216.34.example.com — does not parse and is correctly treated as a
// name, which is why this parses rather than matching strings.
func IsIPTarget(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}
