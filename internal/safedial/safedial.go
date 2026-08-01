// Package safedial provides a dialer that refuses to open connections to
// private, loopback, link-local, or otherwise non-public IP addresses.
//
// It exists because denyfirst runs user-supplied hostnames through
// server-side network probes. Without this guard a visitor could aim the
// scanner at 127.0.0.1, at an RFC 1918 range, or at the cloud metadata
// endpoint (169.254.169.254) and use the service as an SSRF proxy into our
// own infrastructure.
//
// Two properties matter and are easy to get wrong:
//
//   - The hostname is resolved exactly once. The resolved IP is inspected and
//     then dialled directly. A dialer that resolves for the check and lets the
//     OS resolve again for the connection is open to DNS rebinding: the
//     attacker returns a public address for the first lookup and a private one
//     for the second.
//
//   - Addresses are unmapped before inspection. ::ffff:127.0.0.1 is an IPv6
//     address that is really loopback; without Unmap it passes every check.
package safedial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// ErrBlocked is returned when a target is refused by policy rather than by a
// network failure. Callers should surface this to the user as "we will not
// scan that", not as "the scan failed".
var ErrBlocked = errors.New("safedial: destination not permitted")

// blockedPrefixes covers ranges that netip.Addr has no predicate for.
// Loopback, private (RFC 1918 and RFC 4193 ULA), link-local, multicast and
// unspecified are handled by the predicates in checkAddr.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, includes broadcast
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4, can embed IPv4
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64, can embed IPv4
	netip.MustParsePrefix("100::/64"),        // discard-only
}

// Dialer opens TCP connections to public addresses only. The zero value is
// usable: it applies a ten second timeout and permits any port.
type Dialer struct {
	// Timeout bounds a single connection attempt. Zero means ten seconds.
	Timeout time.Duration

	// AllowedPorts, when non-empty, restricts which destination ports may be
	// dialled. Values are decimal strings, for example "443".
	AllowedPorts []string

	// Resolver overrides the system resolver. Nil means net.DefaultResolver.
	Resolver *net.Resolver
}

const defaultTimeout = 10 * time.Second

// DialContext matches the signature expected by http.Transport.DialContext and
// by tls.Dialer.NetDialer, so a Dialer can be dropped into either.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("%w: network %q is not tcp", ErrBlocked, network)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("safedial: bad address %q: %w", address, err)
	}

	if err := checkHost(host); err != nil {
		return nil, err
	}
	if err := d.checkPort(port); err != nil {
		return nil, err
	}

	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	addrs, err := resolver.LookupNetIP(ctx, lookupNetwork(network), host)
	if err != nil {
		return nil, fmt.Errorf("safedial: resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("safedial: %q resolved to no addresses", host)
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	inner := net.Dialer{Timeout: timeout}

	var blocked, dialErr error
	for _, addr := range addrs {
		addr = addr.Unmap()

		if err := checkAddr(addr); err != nil {
			if blocked == nil {
				blocked = err
			}
			continue
		}

		// Dial the inspected literal, never the hostname. This is what closes
		// the rebinding window.
		conn, err := inner.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if err != nil {
			if dialErr == nil {
				dialErr = err
			}
			continue
		}
		return conn, nil
	}

	// Every candidate was refused by policy: report that, not a network error.
	if dialErr == nil && blocked != nil {
		return nil, blocked
	}
	if dialErr != nil {
		return nil, fmt.Errorf("safedial: connect %q: %w", address, dialErr)
	}
	return nil, fmt.Errorf("%w: %q has no usable public address", ErrBlocked, host)
}

// Dial is DialContext with a background context.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *Dialer) checkPort(port string) error {
	if len(d.AllowedPorts) == 0 {
		return nil
	}
	for _, allowed := range d.AllowedPorts {
		if port == allowed {
			return nil
		}
	}
	return fmt.Errorf("%w: port %q is not in the allow list", ErrBlocked, port)
}

// checkHost rejects input that should never reach the resolver. It is a
// sanity gate, not a hostname validator; the resolver rejects the rest.
func checkHost(host string) error {
	switch {
	case host == "":
		return fmt.Errorf("%w: empty host", ErrBlocked)
	case len(host) > 253:
		return fmt.Errorf("%w: host exceeds 253 bytes", ErrBlocked)
	case strings.ContainsAny(host, " \t\r\n\x00"):
		return fmt.Errorf("%w: host contains control or space characters", ErrBlocked)
	}
	return nil
}

// CheckAddr reports whether a single address may be dialled. It is exported so
// that callers can pre-validate a target and return a clear message before any
// network activity happens.
func CheckAddr(addr netip.Addr) error {
	return checkAddr(addr.Unmap())
}

// checkAddr expects an already-unmapped address.
func checkAddr(addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrBlocked)
	}

	var reason string
	switch {
	case addr.IsUnspecified():
		reason = "unspecified"
	case addr.IsLoopback():
		reason = "loopback"
	case addr.IsPrivate():
		reason = "private"
	case addr.IsLinkLocalUnicast():
		// 169.254.0.0/16 — this is the cloud metadata range.
		reason = "link-local"
	case addr.IsLinkLocalMulticast():
		reason = "link-local multicast"
	case addr.IsInterfaceLocalMulticast():
		reason = "interface-local multicast"
	case addr.IsMulticast():
		reason = "multicast"
	}
	if reason != "" {
		return fmt.Errorf("%w: %s is %s", ErrBlocked, addr, reason)
	}

	for _, prefix := range blockedPrefixes {
		// Contains is false across address families, so this is safe for both.
		if prefix.Contains(addr) {
			return fmt.Errorf("%w: %s is inside reserved range %s", ErrBlocked, addr, prefix)
		}
	}

	return nil
}

func lookupNetwork(network string) string {
	switch network {
	case "tcp4":
		return "ip4"
	case "tcp6":
		return "ip6"
	default:
		return "ip"
	}
}
