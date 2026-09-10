package httpapi

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/scan"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// A check is one thing this service can be asked to measure.
//
// It exists so that there is one chain of guards rather than one per endpoint.
// Of the eighteen steps between a request arriving and a report being written,
// twelve are identical for every check: the client key, the read allowance,
// the cross-site test, the content type, the scan allowance, the body cap, the
// JSON decode, the exclusion list, the deployment list, the deadline, the
// concurrency cap and the per-target budget. A second handler would copy all
// twelve, and N6 is written about exactly that — a guard in one place is a
// guard somebody walks around by adding an entry point, and adding entry
// points is what this project is now doing.
//
// So the differences are described here and the chain is written once.
type check struct {
	// name is the key this check is counted under. checkTLS or checkWeb.
	name string

	// parse turns what a caller sent into something this check can measure,
	// or the refusal to answer with.
	//
	// Validity before permission (N6): a target is checked for being a target
	// at all before it is checked against any list, because asked the other
	// way round a deployment answers "this is not something we demonstrate"
	// to somebody who simply mistyped, which tells them the wrong thing about
	// their own mistake.
	parse func(string) (target, *refusal)

	// run performs the measurement.
	run func(context.Context, target) (outcome, error)
}

// target is one thing to measure, after parsing and before permission.
type target struct {
	// host is the folded name (I7). It is what the exclusion list, the
	// deployment list, the limiter and the scanner all see, so that one
	// spelling reaches every one of them.
	host string

	// port is what the caller asked for, or the default. Empty for a check
	// that takes no port.
	port string

	// scope is the second dimension of the per-target budget.
	//
	// It is the port for the TLS check, so that scanning one host on two
	// ports is two budgets, which is what a server experiences. The web check
	// passes the HTTPS port rather than a name of its own, and that is a
	// decision rather than a convenience: this is the only limit here that
	// protects the server being measured rather than this service, and it had
	// no say in being measured at all. A separate budget would let one host
	// be made to absorb twice the peak, and would hand a prober two
	// independent questions about it instead of one. A web check is mostly
	// HTTPS, so it spends the HTTPS budget and competes with a TLS scan of
	// the same host, which is the stricter reading and the simpler one.
	scope string
}

// outcome is what a check established, in the terms the handler needs.
type outcome struct {
	verdict policy.Verdict

	// blocked reports that every attempt was refused by safedial: the name
	// resolves only to addresses this service will not connect to. Answered
	// as a refusal with its own code rather than as a report of failures,
	// because it is the only place it can be counted (A7).
	blocked bool

	// body is what is written on success.
	body any
}

// refusal is an answer that is not a report.
type refusal struct {
	status  int
	code    string
	message string
}

// tlsCheck measures the handshake and the certificate behind it.
func (s *Server) tlsCheck() check {
	return check{
		name:  checkTLS,
		parse: parseTLSTarget,
		run: func(ctx context.Context, t target) (outcome, error) {
			result, err := s.scanner.Scan(ctx, net.JoinHostPort(t.host, t.port))
			if err != nil {
				return outcome{}, err
			}
			return outcome{
				verdict: result.Verdict,
				blocked: result.TLS != nil && result.TLS.BlockedDestination,
				body: scanResponse{
					Result:   result,
					Findings: result.Findings(),
					Notes:    result.Notes(),
				},
			}, nil
		},
	}
}

// webCheck measures how a site is reached over HTTP.
func (s *Server) webCheck() check {
	return check{
		name:  checkWeb,
		parse: parseWebTarget,
		run: func(ctx context.Context, t target) (outcome, error) {
			result, err := s.web.Scan(ctx, t.host)
			if err != nil {
				return outcome{}, err
			}
			return outcome{
				verdict: result.Verdict,
				blocked: result.Observed != nil && result.Observed.BlockedDestination,

				// The result is written as it is. Unlike scan.Result it
				// already carries its findings and its notes, so there is
				// nothing for a wrapper to add and a wrapper would only be a
				// second place for the shape to drift.
				body: result,
			}, nil
		},
	}
}

func parseTLSTarget(raw string) (target, *refusal) {
	host, port, _, err := scan.SplitTargetPort(raw)
	if err != nil {
		// The message describes the rule rather than echoing the input, so
		// nothing a caller sent is reflected back (I3).
		return target{}, &refusal{http.StatusBadRequest, "invalid_target",
			"The target must be a hostname, optionally with a port, and must not contain spaces or control characters."}
	}

	if err := scan.CheckPort(port); err != nil {
		// The rule is described rather than the input repeated. SplitHostPort
		// does not require a port to be numeric, so err.Error() would carry
		// back whatever the caller sent.
		return target{}, &refusal{http.StatusBadRequest, "port_not_allowed",
			"That port is not scannable. This service connects only to " +
				strings.Join(scan.AllowedPorts, ", ") + "."}
	}

	if refused := refuseAnAddress(host); refused != nil {
		return target{}, refused
	}

	return target{host: host, port: port, scope: port}, nil
}

func parseWebTarget(raw string) (target, *refusal) {
	host, _, explicit, err := scan.SplitTargetPort(raw)
	if err != nil {
		return target{}, &refusal{http.StatusBadRequest, "invalid_target", webTargetRule}
	}

	// A port is refused rather than dropped.
	//
	// This check reads a site the way a browser does, over 80 and 443, so
	// there is nothing to choose — but somebody who wrote one has to be told
	// the rule. Ignoring it would be the failure target parsing already
	// refuses for a path: discarding part of what somebody typed without
	// saying so, leaving a report that names the right host while the person
	// is still surprised.
	//
	// port_not_allowed is the wrong sentence here. It names the implicit-TLS
	// ports, which is a rule about a different check.
	if explicit {
		return target{}, &refusal{http.StatusBadRequest, "port_not_accepted",
			"The web check takes a bare hostname. It reads a site over HTTP and HTTPS, the way a " +
				"browser reaches the address somebody types, so there is no port to choose."}
	}

	if refused := refuseAnAddress(host); refused != nil {
		return target{}, refused
	}

	// The probe defines what a target is, so the probe is what is asked. It
	// is exported for exactly this (N6).
	//
	// It refuses nothing target parsing has not already refused: checkHostSyntax
	// requires a domain for the same reason this does, and an address is turned
	// away above under a code of its own. A sabotage that disabled this line
	// therefore changed no answer. It stays because that is two definitions
	// agreeing rather than one definition — loosen the parser and this is what
	// keeps the probe from being handed something it will refuse, which reaches
	// a caller as scan_failed and a 502 instead of as the rule they broke.
	// TestTheHandlerNeverAcceptsATargetTheProbeWouldRefuse holds the agreement.
	if err := webprobe.CheckHostname(host); err != nil {
		return target{}, &refusal{http.StatusBadRequest, "invalid_target", webTargetRule}
	}

	// No port travels with a web target, and the budget it spends is the
	// HTTPS one. See target.scope.
	return target{host: host, scope: scan.DefaultPort}, nil
}

// webTargetRule is spelled once because both branches above state it, and two
// copies of a sentence explaining a rule is how the two come to disagree.
const webTargetRule = "The target must be a hostname with a domain, such as example.com. No scheme, no port, " +
	"no path, and no spaces or control characters."

// refuseAnAddress turns away a bare address, for every check.
//
// The command line accepts addresses; this does not. A scan of a name carries
// that name in the client hello, which is what every browser does, and a scan
// of an address carries none, which is what a scanner does. It also declines
// to lend this address to working through a range one entry at a time.
//
// One code and one sentence whichever check was asked, so that the figure an
// operator watches counts one thing.
func refuseAnAddress(host string) *refusal {
	if !scan.IsIPTarget(host) {
		return nil
	}
	return &refusal{http.StatusBadRequest, "hostname_required",
		"Give a hostname rather than an address. A scan of a name looks like " +
			"an ordinary client to the server receiving it, which is how this " +
			"service prefers to appear. The command line tool accepts addresses " +
			"and runs from your own machine."}
}
