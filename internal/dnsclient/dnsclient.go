// Package dnsclient asks a recursive resolver for record types the standard
// library does not expose.
//
// It exists for one of them. net.Resolver can look up A, AAAA, TXT, MX, NS and
// a few more, and there is no general query. CAA is not among them, so asking
// for CAA means building the message.
//
// That is the whole justification, and it is worth stating because the cost is
// real: everything below parses bytes chosen by whoever answers, which is the
// shape of code this project has found six defects in. What follows is written
// as though the resolver is hostile, because on a plaintext UDP path anyone
// able to answer first is the resolver.
//
// # What this does not do
//
// It does not validate DNSSEC. It reads the AD bit the resolver set and
// reports it, which is a claim about what somebody else did. On a path an
// attacker controls the bit can be flipped like anything else in the message;
// what makes it worth reading at all is that the alternative — running a
// validating resolver here — puts this machine's address in front of every
// nameserver it asks, and that is a change to what a scanned party sees.
//
// It does not cache. A scan asks once and forgets, which is the same promise
// the rest of the service makes.
//
// It does not follow CNAME or DNAME chains. RFC 8659 removed the alias
// handling RFC 6844 had, and the walk up the tree replaces it.
package dnsclient

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	// TypeCAA is the record type from RFC 8659.
	TypeCAA = 257

	classIN = 1
	typeOPT = 41

	// udpPayload is advertised through EDNS0. Larger than the 512 bytes a
	// message without EDNS0 allows, and small enough to survive a path that
	// fragments: 1232 is the figure the DNS Flag Day recommendation settled
	// on, being 1280 minus room for IPv6 and UDP headers.
	udpPayload = 1232

	// maxMessage bounds a reply read over TCP. A CAA answer is a few hundred
	// bytes; anything approaching this is not one.
	maxMessage = 4096

	maxName     = 255
	maxLabel    = 63
	maxPointers = 16

	headerLen = 12
)

// Errors a caller may want to tell apart. Everything else is wrapped.
var (
	ErrNoResolver = errors.New("dnsclient: no resolver configured")
	ErrRefused    = errors.New("dnsclient: the resolver refused the query")
	ErrServerFail = errors.New("dnsclient: the resolver failed the query")
)

// Answer is one reply, already checked against the question that produced it.
type Answer struct {
	// Records holds the CAA properties found, in the order they arrived.
	Records []CAA

	// Name is the domain the records were found at, which is not always the
	// domain that was asked about: CAA is inherited, so a lookup for
	// www.example.com that finds nothing there tries example.com next.
	Name string

	// Validated is the AD bit the resolver set.
	//
	// It means the resolver says it verified the DNSSEC chain. It does not
	// mean this service verified anything, and a report that presents it as
	// though it did is claiming somebody else's work. False is ambiguous by
	// construction: an unsigned zone and a validation this resolver did not
	// attempt look identical from here.
	Validated bool

	// Existed is false when the resolver said the name does not exist.
	// Separate from an empty Records, which means the name exists and has no
	// CAA — the walk up the tree treats those the same but a report should
	// not have to guess which happened.
	Existed bool

	// Queries counts the lookups the walk took, so a caller can charge them
	// against a budget and say so when the budget ran out.
	Queries int
}

// CAA is one property from a CAA record set.
type CAA struct {
	// Critical is the top bit of the flags octet. A property marked critical
	// that an authority does not understand must stop issuance, so an unknown
	// tag carrying it is a different situation from an unknown tag without.
	Critical bool

	// Tag is the property name: issue, issuewild, iodef, and others since.
	Tag string

	// Value is the property value, as text.
	//
	// Chosen by whoever controls the zone, which on a hostile target means
	// chosen by the target. Non-printable bytes are refused during parsing
	// rather than passed on, so what reaches a caller is printable ASCII.
	Value string
}

// Client asks one resolver.
type Client struct {
	// Server is the resolver's address, host and port. Empty means read the
	// system configuration.
	Server string

	// Timeout bounds one exchange. The walk up the tree makes several.
	Timeout time.Duration

	// MaxQueries bounds the walk. CAA is inherited from parents, so a name
	// with many labels could take many lookups, each one telling the resolver
	// about another name.
	MaxQueries int

	// Dial is the network dialler, for tests. Nil means net.Dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

func (c *Client) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 2 * time.Second
	}
	return c.Timeout
}

func (c *Client) maxQueries() int {
	if c.MaxQueries <= 0 {
		return 4
	}
	return c.MaxQueries
}

func (c *Client) server() (string, error) {
	if c.Server != "" {
		return c.Server, nil
	}
	return systemResolver()
}

// LookupCAA walks from name towards the root until it finds a CAA record set
// or runs out of budget.
//
// The walk is what RFC 8659 requires of an authority deciding whether to
// issue: a policy on example.com governs www.example.com unless that name
// carries one of its own. A lookup that stopped at the name asked about would
// report no policy for most of the names that have one.
func (c *Client) LookupCAA(ctx context.Context, name string) (Answer, error) {
	server, err := c.server()
	if err != nil {
		return Answer{}, err
	}

	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	out := Answer{Existed: true}

	for i := 0; i < len(labels) && out.Queries < c.maxQueries(); i++ {
		at := strings.Join(labels[i:], ".")

		reply, err := c.exchange(ctx, server, at, TypeCAA)
		out.Queries++
		if err != nil {
			return out, err
		}

		out.Validated = reply.validated
		out.Existed = reply.existed
		if len(reply.records) > 0 {
			out.Records = reply.records
			out.Name = at
			return out, nil
		}

		// A name that does not exist has no parent worth asking about either,
		// but the parent may still carry a policy that would have governed it
		// had it existed, so the walk continues. What stops is the pretence
		// that the original name was found.
		out.Name = at
	}

	return out, nil
}

type reply struct {
	records   []CAA
	validated bool
	existed   bool
}

func (c *Client) exchange(ctx context.Context, server, name string, qtype uint16) (reply, error) {
	id, err := randomUint16()
	if err != nil {
		return reply{}, fmt.Errorf("dnsclient: generating a query id: %w", err)
	}

	// The question is built once and compared byte for byte against the copy
	// the reply echoes. That comparison is what the randomised case below is
	// for, so the two must be the same bytes rather than the same name.
	question, err := encodeName(name, true)
	if err != nil {
		return reply{}, err
	}

	query := buildQuery(id, question, qtype)

	raw, err := c.roundTrip(ctx, server, query)
	if err != nil {
		return reply{}, err
	}
	return parseReply(raw, id, question, qtype)
}

func (c *Client) roundTrip(ctx context.Context, server string, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	raw, truncated, err := c.exchangeUDP(ctx, server, query)
	if err != nil {
		return nil, err
	}
	if !truncated {
		return raw, nil
	}

	// The reply did not fit. TCP has no such limit, and a resolver that sets
	// the truncation bit is asking for exactly this.
	return c.exchangeTCP(ctx, server, query)
}

func (c *Client) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, network, address)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (c *Client) exchangeUDP(ctx context.Context, server string, query []byte) (raw []byte, truncated bool, err error) {
	conn, err := c.dial(ctx, "udp", server)
	if err != nil {
		return nil, false, fmt.Errorf("dnsclient: reaching the resolver: %w", err)
	}
	defer conn.Close() //nolint:errcheck // nothing was written that a close could fail to flush

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write(query); err != nil {
		return nil, false, fmt.Errorf("dnsclient: sending the query: %w", err)
	}

	// One datagram, bounded by what EDNS0 advertised. A resolver sending more
	// than it was told this side would accept has the truncation bit for that.
	buf := make([]byte, udpPayload)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, fmt.Errorf("dnsclient: reading the reply: %w", err)
	}
	if n < headerLen {
		return nil, false, errors.New("dnsclient: the reply is shorter than a header")
	}

	const truncationBit = 0x0200
	if binary.BigEndian.Uint16(buf[2:4])&truncationBit != 0 {
		return nil, true, nil
	}
	return buf[:n], false, nil
}

func (c *Client) exchangeTCP(ctx context.Context, server string, query []byte) ([]byte, error) {
	conn, err := c.dial(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("dnsclient: reaching the resolver over TCP: %w", err)
	}
	defer conn.Close() //nolint:errcheck // the reply is already read or the error already returned

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)

	if _, err := conn.Write(framed); err != nil {
		return nil, fmt.Errorf("dnsclient: sending the query over TCP: %w", err)
	}

	var length [2]byte
	if _, err := readFull(conn, length[:]); err != nil {
		return nil, fmt.Errorf("dnsclient: reading the reply length: %w", err)
	}

	// The length is the resolver's, so it is checked rather than trusted. A
	// figure accepted as given is an allocation somebody else chose.
	size := int(binary.BigEndian.Uint16(length[:]))
	if size < headerLen || size > maxMessage {
		return nil, fmt.Errorf("dnsclient: the reply announces %d bytes", size)
	}

	raw := make([]byte, size)
	if _, err := readFull(conn, raw); err != nil {
		return nil, fmt.Errorf("dnsclient: reading the reply: %w", err)
	}
	return raw, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := conn.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
		if n == 0 {
			return read, errors.New("dnsclient: the connection returned nothing")
		}
	}
	return read, nil
}

// buildQuery assembles the message.
//
// Two things in the header are defences rather than protocol. The identifier
// is random so that an off-path attacker has to guess it, and the AD bit is
// set because a validating resolver reports its result only when asked. EDNS0
// carries the DO bit for the same reason and raises the size a reply may be.
func buildQuery(id uint16, question []byte, qtype uint16) []byte {
	const (
		recursionDesired = 0x0100
		authenticData    = 0x0020
	)

	msg := make([]byte, 0, headerLen+len(question)+4+11)

	header := make([]byte, headerLen)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], recursionDesired|authenticData)
	binary.BigEndian.PutUint16(header[4:6], 1)   // one question
	binary.BigEndian.PutUint16(header[10:12], 1) // one additional, the OPT below
	msg = append(msg, header...)

	msg = append(msg, question...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, classIN)

	// EDNS0: an OPT pseudo-record on the root name. The class field carries
	// the payload size and the TTL field carries the flags, of which the top
	// bit asks for DNSSEC records.
	const dnssecOK = 0x8000
	msg = append(msg, 0) // root name
	msg = binary.BigEndian.AppendUint16(msg, typeOPT)
	msg = binary.BigEndian.AppendUint16(msg, udpPayload)
	msg = binary.BigEndian.AppendUint32(msg, dnssecOK<<16)
	msg = binary.BigEndian.AppendUint16(msg, 0) // no options

	return msg
}

// encodeName writes a domain name in wire form, optionally randomising case.
//
// The randomisation is the cheapest defence available against an off-path
// forger. A resolver copies the question into its reply unchanged, so a reply
// whose question does not match the exact bytes sent was written by something
// that did not see them. Guessing sixteen bits of identifier is one thing;
// guessing them and the case of every letter is another.
//
// It costs nothing: DNS comparison is case-insensitive, so wWw.ExAmPlE.cOm and
// www.example.com are the same name to everything that matters.
func encodeName(name string, randomiseCase bool) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}
	if len(name) > maxName {
		return nil, fmt.Errorf("dnsclient: the name is %d bytes", len(name))
	}

	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > maxLabel {
			return nil, fmt.Errorf("dnsclient: a label is %d bytes", len(label))
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)

	if randomiseCase {
		if err := randomiseASCIICase(out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func randomiseASCIICase(name []byte) error {
	bits := make([]byte, len(name))
	if _, err := rand.Read(bits); err != nil {
		return fmt.Errorf("dnsclient: randomising the question: %w", err)
	}
	for i, b := range name {
		switch {
		case b >= 'a' && b <= 'z':
			if bits[i]&1 == 1 {
				name[i] = b - 32
			}
		case b >= 'A' && b <= 'Z':
			if bits[i]&1 == 1 {
				name[i] = b + 32
			}
		}
	}
	return nil
}

func randomUint16() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// systemResolver reads the first nameserver from resolv.conf.
//
// Go's resolver reads this file and does not expose what it found, so it is
// read again here. On a system without one — Windows, most notably, where the
// command line tool also runs — this fails and the caller reports that CAA
// could not be checked, which is the honest outcome and not a crash.
func systemResolver() (string, error) {
	raw, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNoResolver, err)
	}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip := net.ParseIP(fields[1]); ip != nil {
			return net.JoinHostPort(fields[1], "53"), nil
		}
	}
	return "", fmt.Errorf("%w: no nameserver line in /etc/resolv.conf", ErrNoResolver)
}
