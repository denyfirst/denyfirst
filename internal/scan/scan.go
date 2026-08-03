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
	"fmt"
	"net"
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
}

// Scanner runs one scan. The zero value is usable and defaults to the
// SSRF-safe dialer.
type Scanner struct {
	Prober *tlsprobe.Prober

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
	return out
}

// SplitTarget normalises a target into a host and a port.
//
// On the command line the input is a typo; over HTTP it is whatever a stranger
// sent. One implementation means the stricter case sets the rules for both.
func SplitTarget(target string) (host, port string, err error) {
	target = strings.TrimSpace(target)

	// A pasted URL is a likely mistake rather than something worth refusing.
	for _, prefix := range []string{"https://", "http://"} {
		if rest, ok := strings.CutPrefix(target, prefix); ok {
			target = rest
		}
	}
	target = strings.TrimSuffix(target, "/")
	if i := strings.IndexByte(target, '/'); i >= 0 {
		target = target[:i]
	}

	host, port, err = net.SplitHostPort(target)
	if err != nil {
		host, port = target, DefaultPort
	}

	switch {
	case host == "":
		return "", "", fmt.Errorf("no host in %q", target)
	case len(host) > maxHostLen:
		return "", "", fmt.Errorf("host exceeds %d bytes", maxHostLen)
	case strings.ContainsAny(host, " \t\r\n\x00"):
		// Trimming removed the harmless case. What is left is interior: a
		// newline inside a hostname is how header injection starts, and a NUL
		// byte is how a truncating parser is made to read a different name
		// than the one that was checked.
		return "", "", fmt.Errorf("host contains control or space characters")
	}

	return host, port, nil
}

// CheckPort reports whether a port may be dialled.
func CheckPort(port string) error {
	for _, allowed := range AllowedPorts {
		if port == allowed {
			return nil
		}
	}
	return fmt.Errorf("port %s is not scannable; this project connects only to %s",
		port, strings.Join(AllowedPorts, ", "))
}
