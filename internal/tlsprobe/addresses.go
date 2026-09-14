package tlsprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/denyfirst/denyfirst/internal/safedial"
)

// AddressAnswer is what one of a name's addresses answered when asked on its own.
//
// # Why this is asked
//
// A scan's handshakes each resolve the name again and reach whichever address
// the resolver hands them, so the report above describes some of a name's
// machines — and AddressesReached says which — while a misconfigured machine
// the resolver did not happen to offer is missed entirely. So each address is
// asked once, pinned: one handshake of the kind a client makes, dialled at that
// address and naming the host. What it answers is compared with what the others
// answer, and the report says whether they agree.
//
// One handshake rather than a scan of each, because a scan is thirteen
// connections and eight addresses would make it a hundred. What one handshake
// shows — the version and suite a client is given and the certificate it is
// shown — is what differs when one machine behind a name is behind the others.
type AddressAnswer struct {
	Address string `json:"address"`

	// Answered is whether a handshake completed.
	Answered bool `json:"answered"`

	Version string `json:"version,omitempty"`
	Suite   string `json:"suite,omitempty"`

	// Certificate is the SHA-256 of the leaf presented, in hex.
	Certificate string `json:"certificate,omitempty"`

	// Reason says why no handshake completed, as a fixed phrase naming nothing
	// about this machine or its network (I6).
	Reason string `json:"reason,omitempty"`
}

// eachAddress asks each of the name's addresses on its own.
//
// Nothing is asked of a name with one address, or of an address given as the
// target: there is nothing to compare, and the report's Address is already it.
// The addresses come from the same resolver the dialler asks, in the order and
// under the cap it uses (safedial.Candidates), and every connection still goes
// through the dialler, so an address it refuses is refused here too (N1).
func (p *Prober) eachAddress(ctx context.Context, host, port string) (answers []AddressAnswer, truncated bool) {
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, false
	}

	addrs, err := p.lookup()(ctx, host)
	if err != nil {
		return nil, false
	}
	seen := map[netip.Addr]bool{}
	var unique []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if !seen[a] {
			seen[a] = true
			unique = append(unique, a)
		}
	}
	candidates, truncated := safedial.Candidates(unique, safedial.DefaultMaxAddrs)
	if len(candidates) < 2 {
		return nil, false
	}

	answers = make([]AddressAnswer, len(candidates))
	var wg sync.WaitGroup
	for i, addr := range candidates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i] = p.answerAt(ctx, host, port, addr)
		}()
	}
	wg.Wait()
	return answers, truncated
}

// answerAt holds one handshake with one address, naming the host.
func (p *Prober) answerAt(ctx context.Context, host, port string, addr netip.Addr) AddressAnswer {
	out := AddressAnswer{Address: net.JoinHostPort(addr.String(), port)}

	ctx, cancel := context.WithTimeout(ctx, p.handshakeTimeout())
	defer cancel()

	conn, err := p.dial()(ctx, "tcp", out.Address)
	if err != nil {
		if errors.Is(err, safedial.ErrBlocked) {
			out.Reason = "not contacted: this is not a destination a scan connects to"
		} else {
			out.Reason = "no connection opened"
		}
		return out
	}
	defer conn.Close()

	// The settings gosec objects to are the purpose, for the reason handshake
	// gives: the certificate is described rather than trusted, and an old
	// version is accepted because an address still negotiating one is the
	// difference this is looking for.
	//
	// #nosec G402 -- deliberate: this is a TLS scanner, not a TLS client
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		out.Reason = "a connection opened and the handshake did not complete"
		return out
	}

	state := tlsConn.ConnectionState()
	out.Answered = true
	out.Version = versionName(state.Version)
	out.Suite = tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		sum := sha256.Sum256(state.PeerCertificates[0].Raw)
		out.Certificate = hex.EncodeToString(sum[:])
	}
	return out
}

// describeAddresses says whether the name's addresses answered alike.
//
// Nothing is graded. No document says a name's machines must be configured
// identically — a migration in progress is exactly a name whose machines are
// not — and the report says what differs so a reader can tell which case it is.
func describeAddresses(report *Report) {
	answers := report.Addresses
	if len(answers) == 0 {
		return
	}

	var (
		answered []AddressAnswer
		silent   []string
		shapes   = map[string]bool{}
	)
	for _, a := range answers {
		if !a.Answered {
			silent = append(silent, a.Address+" ("+a.Reason+")")
			continue
		}
		answered = append(answered, a)
		shapes[a.Version+"|"+a.Suite+"|"+a.Certificate] = true
	}

	switch {
	case len(shapes) > 1:
		var each []string
		for _, a := range answered {
			each = append(each, a.Address+": "+a.Version+" "+a.Suite+", certificate "+shortCertificate(a.Certificate))
		}
		report.observe("The addresses this name resolves to do not answer alike when each is asked on its own — " +
			strings.Join(each, "; ") + ". A client is handed whichever address its resolver gives it, so the " +
			"report above describes some of these machines and not the others.")
	case len(answered) > 1:
		report.observe(fmt.Sprintf("Each of the %s addresses this name resolves to was asked on its own, "+
			"and the %s that answered gave the same version, suite and certificate.",
			strconv.Itoa(len(answers)), countOf(len(answered))))
	}

	if len(silent) > 0 && len(answered) > 0 {
		report.unsettled("Asked on its own, " + strings.Join(silent, "; ") + " did not answer, so whether " +
			thoseMachines(len(silent)) + " answer like the rest is not established.")
	}
	if report.AddressesTruncated {
		report.unsettled(fmt.Sprintf("The name resolves to more addresses than a scan asks on their own, so only "+
			"the first %d were compared.", safedial.DefaultMaxAddrs))
	}
}

// shortCertificate is enough of a fingerprint to tell two apart on a line.
func shortCertificate(sum string) string {
	if sum == "" {
		return "none presented"
	}
	return sum[:min(16, len(sum))] + "…"
}

func countOf(n int) string {
	if n == 2 {
		return "two"
	}
	return strconv.Itoa(n)
}

func thoseMachines(n int) string {
	if n == 1 {
		return "that machine does"
	}
	return "those machines do"
}

// lookup lists a name's addresses. Nil LookupAddrs means the resolver the
// dialler asks, so the two lists are of one name.
func (p *Prober) lookup() func(context.Context, string) ([]netip.Addr, error) {
	if p.LookupAddrs != nil {
		return p.LookupAddrs
	}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
}

// sortedAddresses is the list in the order a reader scans it.
func sortedAddresses(answers []AddressAnswer) []AddressAnswer {
	out := slices.Clone(answers)
	slices.SortStableFunc(out, func(a, b AddressAnswer) int { return strings.Compare(a.Address, b.Address) })
	return out
}
