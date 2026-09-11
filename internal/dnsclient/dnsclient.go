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
	"strings"
	"time"
)

const (
	// TypeCAA is the record type from RFC 8659.
	TypeCAA = 257

	// TypeTXT is the record type from RFC 1035.
	TypeTXT = 16

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

	// maxResolvers bounds how many of a machine's configured resolvers one
	// lookup will try. resolv.conf's own limit is three; Windows can hold more
	// across several adapters. A bound rather than a rule: a machine with more
	// than this is one to read the beginning of, not a reason to read none.
	maxResolvers = 6

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

	// Existed is false when the resolver said the name asked about does not
	// exist. Separate from an empty Records, which means the name exists and
	// has no CAA: the walk up the tree treats those the same, and a report
	// should not have to guess which happened.
	//
	// It describes the name that was asked about and nothing else. The walk
	// continues past a name that does not exist, because a parent may carry a
	// policy that would have governed it, and taking this from wherever the
	// walk ended would report a name as existing on the strength of its
	// grandparent existing.
	Existed bool

	// Complete is false when the walk ran out of budget before it reached the
	// top of the name.
	//
	// An empty Records list means one of two things, and they lead to
	// opposite conclusions. The walk reached the root and found no policy, so
	// any authority may issue — or the walk stopped partway and the name that
	// carries the policy was never asked. A caller that cannot tell them
	// apart will publish the first sentence in both cases, which is how a
	// restricted name comes to be reported as unrestricted.
	Complete bool

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
	// with many labels could take many lookups.
	//
	// Six rather than four since 2026-08-22, and the two extra are not
	// arbitrary. The walk goes label by label towards the root, so a budget of
	// four stops after four names — which reaches the registrable domain for
	// anything up to five labels and misses it from six. a.b.c.d.example.com
	// was answered by searching as far as d.example.com and concluding that
	// any authority may issue for it, while example.com may carry a policy
	// governing the whole tree. Six covers seven labels, which is past
	// anything ordinary.
	//
	// It is still a bound, so it can still stop short, and Answer.Complete
	// now says when it did. A budget that quietly changes the meaning of the
	// answer is worse than a smaller one that admits it.
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
		return 6
	}
	return c.MaxQueries
}

func (c *Client) servers() ([]string, error) {
	if c.Server != "" {
		return []string{c.Server}, nil
	}
	return systemResolvers()
}

// resolverList turns the addresses a platform found into the list a lookup will
// ask, in the order they were found.
//
// Here rather than in each platform's file, which is where it was first
// written. Two copies of "skip what cannot be dialled, drop a repeat, stop at
// the bound" are two copies that drift, and only one of them can be tested on
// any given machine: a sabotage that stopped suppressing duplicates passed
// every test, because the machine running them happens to have none. One
// implementation, tested on every platform.
//
// What each rule is for:
//
//   - An address that will not parse, or names no host, is a timeout spent to
//     learn nothing. 0.0.0.0 appears in a Windows registry as a placeholder and
//     is the commonest of them.
//   - A repeat is the same timeout paid twice. One router's address under both
//     a wired and a wireless adapter is the ordinary way to get one.
//   - The bound is a bound. A machine with more configured resolvers than this
//     is one to read the beginning of, not a reason to read none of it — but a
//     lookup that tried every entry of a long list would outlast the scan that
//     asked for it.
func resolverList(addrs []string) []string {
	var out []string
	seen := map[string]bool{}

	for _, raw := range addrs {
		if len(out) >= maxResolvers {
			break
		}

		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || ip.IsUnspecified() {
			continue
		}

		at := net.JoinHostPort(ip.String(), "53")
		if seen[at] {
			continue
		}
		seen[at] = true
		out = append(out, at)
	}
	return out
}

// resolverSet is the resolvers one lookup may ask, and which of them last
// answered.
//
// A machine configures more than one on purpose, and the second is there
// because the first is allowed to be unreachable. Asking only the first is how
// a check that works everywhere reports "not checked" on a laptop whose primary
// resolver belongs to a virtual adapter — which is what every scan on this
// project's own development machine did until this existed.
//
// Remembering the one that answered is what keeps the cost bounded. A CAA walk
// makes up to six queries, and paying a dead resolver's timeout on each of them
// would spend more of the scan budget than the whole check is worth. It is paid
// once.
type resolverSet struct {
	servers []string
	chosen  int
}

// ask sends one query, moving to the next resolver until one answers.
//
// An answer includes "that name does not exist": exchange reports that as a
// reply rather than as an error, so a walk is never restarted over a name that
// simply is not there. What moves to the next resolver is a resolver that could
// not be reached, refused the query, or failed it — the three a stub resolver
// treats the same way, because none of them is an answer about the name.
//
// The first error is the one returned when every resolver is exhausted, so a
// caller that distinguishes ErrRefused from ErrServerFail still can.
func (c *Client) ask(ctx context.Context, set *resolverSet, name string, qtype uint16) (reply, error) {
	if len(set.servers) == 0 {
		return reply{}, ErrNoResolver
	}

	var first error
	for i := range set.servers {
		at := (set.chosen + i) % len(set.servers)

		r, err := c.exchange(ctx, set.servers[at], name, qtype)
		if err == nil {
			set.chosen = at
			return r, nil
		}
		if first == nil {
			first = err
		}
	}
	return reply{}, first
}

// LookupCAA walks from name towards the root until it finds a CAA record set
// or runs out of budget.
//
// The walk is what RFC 8659 requires of an authority deciding whether to
// issue: a policy on example.com governs www.example.com unless that name
// carries one of its own. A lookup that stopped at the name asked about would
// report no policy for most of the names that have one.
func (c *Client) LookupCAA(ctx context.Context, name string) (Answer, error) {
	servers, err := c.servers()
	if err != nil {
		return Answer{}, err
	}
	set := &resolverSet{servers: servers}

	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	out := Answer{Existed: true}

	// Complete until the budget says otherwise. A walk that ran out partway
	// and one that reached the top produce the same empty record list, and
	// only one of them supports the sentence "no authority is restricted".
	out.Complete = len(labels) <= c.maxQueries()

	for i := 0; i < len(labels) && out.Queries < c.maxQueries(); i++ {
		at := strings.Join(labels[i:], ".")

		reply, err := c.ask(ctx, set, at, TypeCAA)
		out.Queries++
		if err != nil {
			return out, err
		}

		out.Validated = reply.validated
		if i == 0 {
			out.Existed = reply.existed
		}
		if len(reply.records) > 0 {
			out.Records = reply.records
			out.Name = at
			return out, nil
		}

		// The walk continues past a name that does not exist, because the
		// parent may carry a policy. Existed is not touched here: it was set
		// on the first pass and describes the name that was asked about.
		out.Name = at
	}

	return out, nil
}

type reply struct {
	records []CAA

	// txt holds the TXT record values found, one entry per record.
	//
	// A separate field rather than a second use of records, because the two
	// carry different things and a caller that had to switch on which one was
	// filled would be reading the query type back out of the answer.
	txt []string

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

	// TCP frames a message with its length in two bytes, so a query longer
	// than those two bytes can express cannot be sent at all. It never is —
	// a CAA question is a few dozen bytes — but the conversion below is
	// narrowing, and a narrowing conversion that nothing checks is how a
	// length silently becomes a different, smaller length.
	querySize := len(query)
	if querySize > maxMessage {
		return nil, fmt.Errorf("dnsclient: the query is %d bytes, more than %d", querySize, maxMessage)
	}
	framed := make([]byte, 2+querySize)
	binary.BigEndian.PutUint16(framed, uint16(querySize))
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
		// maxLabel is 63, which is what the two high bits of a length byte
		// being reserved for compression pointers leaves. The check is the
		// protocol's; it also happens to be what makes the conversion below
		// safe, and stating that here is cheaper than discovering later that
		// removing one broke the other.
		length := len(label)
		if length == 0 || length > maxLabel {
			return nil, fmt.Errorf("dnsclient: a label is %d bytes", length)
		}
		out = append(out, byte(length))
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

// systemResolver returns the resolver this machine is configured to ask, as
// host:port.
//
// It is per platform, in resolver_unix.go and resolver_windows.go, because the
// answer lives in a different place on each and there is no portable way to
// ask. Go's own resolver knows, and does not expose what it found.
//
// Reading the machine's own configuration is the point rather than an
// implementation detail. A CAA lookup goes to the resolver this machine
// already asks about every target, so the scan tells nobody anything they were
// not already going to be told. Falling back to a public resolver when the
// local one cannot be found would quietly move that, which is a change to who
// learns what is being scanned — so instead the lookup fails, and the report
// says the check did not happen (R4).
//
// Client.Server overrides it, and an operator whose machine this guesses wrong
// about should set it rather than work around it.

// TXTAnswer is what a TXT lookup found.
type TXTAnswer struct {
	// Values holds one entry per TXT record at the name, in the order they
	// arrived. A record split across several character-strings is joined.
	Values []string

	// Existed is false when the resolver said the name does not exist.
	// Separate from an empty Values, which means the name exists and carries
	// no TXT: a caller that could not tell them apart would report "no proof
	// published" for a domain that does not exist, and the two lead a reader
	// to different places.
	Existed bool

	// Validated is the AD bit the resolver set. It means the resolver says it
	// verified the DNSSEC chain, not that this program verified anything, and
	// a caller presenting it as its own work would be claiming somebody
	// else's.
	Validated bool
}

// LookupTXT reads the TXT records at one name.
//
// No walk up the tree, which is the difference from LookupCAA and the whole of
// it. CAA is inherited, so a name with none is governed by its parent's; a
// challenge is not, and a walk would let a record published at example.com
// prove control of a name delegated to somebody else — the failure
// docs/scope.md is written about, arriving through the lookup instead of
// through the rule.
func (c *Client) LookupTXT(ctx context.Context, name string) (TXTAnswer, error) {
	servers, err := c.servers()
	if err != nil {
		return TXTAnswer{}, err
	}

	reply, err := c.ask(ctx, &resolverSet{servers: servers}, name, TypeTXT)
	if err != nil {
		return TXTAnswer{Existed: reply.existed, Validated: reply.validated}, err
	}

	return TXTAnswer{
		Values:    reply.txt,
		Existed:   reply.existed,
		Validated: reply.validated,
	}, nil
}

// LookupChallenge reads TXT records in the narrow shape a boundary asks for.
//
// internal/verify decides what may be scanned and deliberately imports nothing
// of this project's own, the way internal/policy does: a rule about who may be
// reached should be readable without reading a DNS client. So the adapter is
// here rather than there, and it is one method rather than a closure written
// at every place a scope is constructed.
//
// Validated is dropped on purpose. It is the resolver's claim that it checked
// DNSSEC, and a boundary that treated it as its own work would be presenting
// somebody else's verification as this program's — the same objection the CAA
// report already makes about the same bit.
func (c *Client) LookupChallenge(ctx context.Context, name string) (values []string, existed bool, err error) {
	answer, err := c.LookupTXT(ctx, name)
	return answer.Values, answer.Existed, err
}
