// Package safedial provides a dialer that refuses to open connections to
// private, loopback, link-local, or otherwise non-public IP addresses.
//
// It exists because denyfirst runs user-supplied hostnames through
// server-side network probes. Without this guard a visitor could aim the
// scanner at 127.0.0.1, at an RFC 1918 range, or at the cloud metadata
// endpoint (169.254.169.254) and use the service as an SSRF proxy into our
// own infrastructure.
//
// Four properties matter and are each easy to get wrong:
//
//   - The hostname is resolved exactly once. The resolved IP is inspected and
//     then dialled directly. A dialer that resolves for the check and lets the
//     OS resolve again for the connection is open to DNS rebinding: the
//     attacker returns a public address for the first lookup and a private one
//     for the second.
//
//   - Addresses are unmapped before inspection. ::ffff:127.0.0.1 is an IPv6
//     address that is really loopback; without Unmap it passes every check.
//
//   - The number of addresses tried is capped. A hostname served by an
//     attacker-controlled nameserver can resolve to hundreds of addresses.
//     Without a cap, one request turns into hundreds of connection attempts.
//
//   - The whole operation shares one time budget. A per-attempt timeout alone
//     multiplies: eight addresses at ten seconds each is eighty seconds of
//     work for a single request.
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
//
// The IPv6 entries that embed an IPv4 address are the ones that matter, and
// they are the ones easiest to leave out. A predicate such as IsLoopback
// answers for the address it is given, not for the address hidden inside it:
// ::127.0.0.1 is an IPv4-compatible IPv6 address whose low thirty-two bits
// are loopback, and every predicate in checkAddr says it is an ordinary
// global address. Unmap does not help either — it rewrites ::ffff:a.b.c.d and
// nothing else. Each family of embedded address therefore needs its own line
// here, and 2001::/23 covers several at once because IANA reserved that block
// for exactly this kind of protocol assignment.
//
// This is a deny list, which is the shape this file argues against elsewhere.
// The honest reason is that the standard library offers no predicate for "in
// a range IANA has delegated to somebody", so an allow list would mean
// carrying a copy of the delegation registry and keeping it current. The
// exchange is stated rather than hidden: a range added to the special-purpose
// registry after this line was written is not covered until somebody adds it,
// and security-watch.yml exists partly to make that a thing somebody looks at.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.31.196.0/24"), // AS112-v4
	netip.MustParsePrefix("192.52.193.0/24"), // AMT relay anycast
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast
	netip.MustParsePrefix("192.175.48.0/24"), // direct delegation AS112
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, includes broadcast

	// ::/96 is the deprecated IPv4-compatible form from RFC 4291. It is the
	// one that matters most here: ::127.0.0.1 and ::10.0.0.1 are written this
	// way, no predicate in checkAddr recognises either, and some stacks have
	// historically routed them to the embedded address. Nothing legitimate is
	// reachable inside it, so blocking the whole /96 costs nothing.
	netip.MustParsePrefix("::/96"),

	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64, embeds IPv4
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64, embeds IPv4
	netip.MustParsePrefix("100::/64"),       // discard-only

	// 2001::/23 is IANA's special-purpose block, the IPv6 counterpart of
	// 192.0.0.0/24. One prefix covers Teredo (2001::/32, which carries an
	// IPv4 client address in its low bits), benchmarking, AMT, AS112-v6, both
	// ORCHID versions and DRIP. Global unicast begins well above it —
	// 2001:db8::/32 and 2001:4860::/32 are both outside — so the documentation
	// range below still needs its own line.
	netip.MustParsePrefix("2001::/23"),

	netip.MustParsePrefix("2001:db8::/32"), // documentation
	netip.MustParsePrefix("2002::/16"),     // 6to4, embeds IPv4
	netip.MustParsePrefix("3fff::/20"),     // documentation, RFC 9637
	netip.MustParsePrefix("5f00::/16"),     // SRv6 segment identifiers, RFC 9602
}

const (
	defaultTimeout      = 10 * time.Second
	defaultTotalTimeout = 30 * time.Second
	defaultMaxAddrs     = 8
)

// Dialer opens TCP connections to public addresses only. The zero value is
// usable and applies the defaults documented on each field.
type Dialer struct {
	// Timeout bounds a single connection attempt. Zero means ten seconds.
	Timeout time.Duration

	// TotalTimeout bounds the entire operation, resolution included, however
	// many addresses are tried. Zero means thirty seconds. If the context
	// passed to DialContext expires sooner, the context wins.
	TotalTimeout time.Duration

	// MaxAddrs caps how many resolved addresses are attempted. Zero means
	// eight. Anything beyond the cap is ignored.
	MaxAddrs int

	// AllowedPorts, when non-empty, restricts which destination ports may be
	// dialled. Values are decimal strings, for example "443".
	AllowedPorts []string

	// Resolver overrides the system resolver. Nil means net.DefaultResolver.
	Resolver *net.Resolver
}

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

	// One budget for resolution and every attempt together. WithTimeout keeps
	// whichever deadline is earlier, so a caller with a tighter deadline is
	// never overridden.
	ctx, cancel := context.WithTimeout(ctx, d.totalTimeout())
	defer cancel()

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

	limit := d.maxAddrs()
	addrs, truncated := interleaveFamilies(addrs, limit)

	inner := net.Dialer{Timeout: d.perAttemptTimeout()}

	var blocked, dialErr error
	for _, addr := range addrs {
		// Stop as soon as the shared budget is gone rather than starting an
		// attempt that cannot finish.
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("safedial: %q: %w%s", address, err, truncNote(truncated, limit))
		}

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
		return nil, fmt.Errorf("%w%s", blocked, truncNote(truncated, limit))
	}
	if dialErr != nil {
		return nil, fmt.Errorf("safedial: connect %q: %w%s", address, dialErr, truncNote(truncated, limit))
	}
	return nil, fmt.Errorf("%w: %q has no usable public address%s", ErrBlocked, host, truncNote(truncated, limit))
}

// Dial is DialContext with a background context.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *Dialer) perAttemptTimeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return defaultTimeout
}

func (d *Dialer) totalTimeout() time.Duration {
	if d.TotalTimeout > 0 {
		return d.TotalTimeout
	}
	return defaultTotalTimeout
}

func (d *Dialer) maxAddrs() int {
	if d.MaxAddrs > 0 {
		return d.MaxAddrs
	}
	return defaultMaxAddrs
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

// truncNote explains a partial result so a failure is not mistaken for a
// complete one.
func truncNote(truncated bool, limit int) string {
	if !truncated {
		return ""
	}
	return fmt.Sprintf(" (only the first %d resolved addresses were considered)", limit)
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

// interleaveFamilies orders addresses so both families are represented, then
// caps the list.
//
// The cap exists so one hostname cannot spend the whole budget, and taking the
// first n in resolver order looked like a fair way to apply it. It is not. A
// resolver returns AAAA and A records in whatever order it likes, and a large
// content network answers with many of each. Take the first eight and they can
// all be one family — which matters because a host may have no route for that
// family at all.
//
// This is the failure that follows. Every attempt fails with "network
// unreachable", the dialler reports the target as unreachable, and the person
// reading the report concludes the server they scanned is down. It is not. Ours
// is the machine that cannot reach it, and the report accuses the wrong party.
// A scanner whose argument is that it says only what it measured cannot afford
// to say that.
//
// Alternating between the families before cutting means a budget of eight
// always carries at least four of each, wherever the resolver put them, so a
// reachable address is always tried. This is the ordering RFC 8305 describes
// and browsers have used for years.
//
// Order within a family is preserved: a resolver that rotates records for load
// balancing keeps doing so.
func interleaveFamilies(addrs []netip.Addr, limit int) (out []netip.Addr, truncated bool) {
	if len(addrs) <= limit {
		return addrs, false
	}

	var v4, v6 []netip.Addr
	for _, addr := range addrs {
		if addr.Unmap().Is4() {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}

	// One family absent is the ordinary case, and alternating with nothing is
	// the same list back again.
	if len(v4) == 0 || len(v6) == 0 {
		return addrs[:limit], true
	}

	out = make([]netip.Addr, 0, limit)
	for i := 0; len(out) < limit; i++ {
		if i < len(v4) {
			out = append(out, v4[i])
		}
		if len(out) < limit && i < len(v6) {
			out = append(out, v6[i])
		}
	}
	return out, true
}
