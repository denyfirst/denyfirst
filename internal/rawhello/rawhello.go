// Package rawhello asks a server whether it will answer a ClientHello offering
// something Go's TLS client cannot offer: SSL 3.0, the export-grade and NULL
// cipher suites, and a downgraded hello carrying TLS_FALLBACK_SCSV.
//
// # Why this is written by hand
//
// crypto/tls implements neither SSL 3.0 nor any export-grade or NULL suite, and
// it is not going to. Until this package existed, a server still accepting any
// of them was measured by this project through a client that could not offer
// them — so a server speaking only SSL 3.0 was reported as refusing every
// version. That is the flattering direction, on exactly the servers that most
// need the finding.
//
// # What it does, and what it deliberately does not
//
// It writes one ClientHello, reads the first record that comes back, and stops.
// From that record it reads at most whether it is an alert or a ServerHello, the
// version the server chose and the suite it chose. That is under eighty bytes,
// and it is the whole of what is parsed.
//
// No handshake is completed. No certificate is read, no key is exchanged, and
// nothing is sent after the hello. A server that answers learns that somebody
// asked which of these it would speak — which is what every scanner of this kind
// asks — and is sent nothing that makes use of the answer.
//
// The reply is written by whoever is being measured, so every length in it is
// checked before it is believed, and nothing is read past what those checks
// allow.
package rawhello

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"strings"
	"time"
)

// Record and handshake values from RFC 5246, which SSL 3.0 shares.
const (
	contentAlert     = 21
	contentHandshake = 22

	typeClientHello = 1
	typeServerHello = 2

	alertFatal = 2

	// maxRecord is the largest record a peer may send: 2^14 bytes of plaintext
	// and the 2048 RFC 5246 allows for expansion. A header claiming more is not
	// a TLS record, whatever else it is.
	maxRecord = 1<<14 + 2048

	// serverHelloFixed is the part of a ServerHello before the session id:
	// version, random, and the session id's length byte.
	serverHelloFixed = 2 + 32 + 1

	// maxSessionID is the longest session id RFC 5246 permits.
	maxSessionID = 32

	// maxSuites bounds what one hello offers. Every list in this package is far
	// below it; it exists so that a caller cannot make one hello enormous.
	maxSuites = 128

	// maxServerName is the longest name DNS allows.
	maxServerName = 253
)

// Alert descriptions a caller has reason to tell apart.
const (
	// AlertInappropriateFallback is what RFC 7507 tells a server to send when
	// a hello carries TLS_FALLBACK_SCSV and claims less than the server speaks.
	AlertInappropriateFallback = 86
)

// FallbackSCSV is the signalling value RFC 7507 defines. Offered as a suite and
// never negotiated as one.
const FallbackSCSV uint16 = 0x5600

// Answer is what the first record back amounted to.
type Answer string

const (
	// Accepted means a ServerHello came back: the server chose a version and a
	// suite from what was offered.
	Accepted Answer = "accepted"

	// Refused means a fatal alert came back. The server read the hello and
	// declined it.
	Refused Answer = "refused"

	// Unanswered is everything else — a closed connection, a timeout, a reset,
	// something that is not TLS. None of those is a refusal. A server that
	// closes the connection rather than sending an alert is common, and so is a
	// firewall that does the same on its behalf; reading either as the server's
	// decision would be crediting it with one it may never have made (R4).
	Unanswered Answer = "unanswered"
)

// Errors describing a reply that could not be read. Never rendered to anybody:
// a caller turns them into a fixed phrase (I6).
var (
	ErrNotTLS         = errors.New("rawhello: the reply is not a tls record")
	ErrNotServerHello = errors.New("rawhello: the reply is not a server hello")
	ErrSplit          = errors.New("rawhello: the server hello does not fit in the first record")

	errNoSuites       = errors.New("rawhello: a hello must offer at least one suite")
	errTooManySuites  = errors.New("rawhello: a hello offers more suites than this package sends")
	errBadVersion     = errors.New("rawhello: a hello must name an ssl 3.0 or tls version")
	errNotAnswerAlert = errors.New("rawhello: a warning alert is not a refusal")
)

// Result is one reply, reduced to what this package reads.
type Result struct {
	Answer Answer

	// Version and Suite are the server's choices, when it accepted.
	Version uint16
	Suite   uint16

	// Alert is the alert description, when it refused.
	Alert uint8

	// Err is why nothing could be read, when it did neither. For a caller to
	// classify and never to show.
	Err error
}

// Hello is one ClientHello to send.
type Hello struct {
	// RecordVersion is the version on the record layer. SSL 3.0 for an SSL 3.0
	// hello; TLS 1.0 for everything else, which is what clients have sent for
	// years because some servers refuse a higher one there.
	RecordVersion uint16

	// ClientVersion is the highest version the hello claims.
	ClientVersion uint16

	// Suites are offered in this order.
	Suites []uint16

	// Extensions adds server_name, supported_groups, ec_point_formats and
	// signature_algorithms. Without the middle two a server cannot choose an
	// elliptic-curve suite at all, so a TLS hello offering one needs them.
	//
	// Off for SSL 3.0, which predates extensions. A server of that era is
	// meant to ignore them and some do not; the question being asked is
	// whether it speaks SSL 3.0, not whether it survives bytes it never knew.
	Extensions bool

	// ServerName is sent when Extensions is on and it is a hostname. An
	// address is never sent as one: RFC 6066 forbids it.
	ServerName string
}

// Marshal writes the hello as a record.
func (h Hello) Marshal() ([]byte, error) {
	switch {
	case len(h.Suites) == 0:
		return nil, errNoSuites
	case len(h.Suites) > maxSuites:
		return nil, errTooManySuites
	case h.RecordVersion>>8 != 3 || h.ClientVersion>>8 != 3:
		return nil, errBadVersion
	}

	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}

	body := binary.BigEndian.AppendUint16(nil, h.ClientVersion)
	body = append(body, random...)
	body = append(body, 0) // no session id: nothing is being resumed

	body = binary.BigEndian.AppendUint16(body, u16(2*len(h.Suites)))
	for _, s := range h.Suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}

	// One compression method, null. Offering DEFLATE would be asking about
	// CRIME, which is a different question and not one this package asks.
	body = append(body, 1, 0)

	if h.Extensions {
		ext := extensions(h.ServerName)
		body = binary.BigEndian.AppendUint16(body, u16(len(ext)))
		body = append(body, ext...)
	}

	msg := []byte{typeClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	msg = append(msg, body...)

	record := []byte{contentHandshake}
	record = binary.BigEndian.AppendUint16(record, h.RecordVersion)
	record = binary.BigEndian.AppendUint16(record, u16(len(msg)))
	return append(record, msg...), nil
}

// signatureAlgorithms are what a TLS 1.2 client of the last decade offers.
// Without the extension a TLS 1.2 server assumes SHA-1, and some refuse.
var signatureAlgorithms = []uint16{
	0x0403, // ecdsa_secp256r1_sha256
	0x0804, // rsa_pss_rsae_sha256
	0x0401, // rsa_pkcs1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0805, // rsa_pss_rsae_sha384
	0x0501, // rsa_pkcs1_sha384
	0x0601, // rsa_pkcs1_sha512
	0x0203, // ecdsa_sha1
	0x0201, // rsa_pkcs1_sha1
}

// groups are the curves an elliptic-curve suite can be negotiated over.
var groups = []uint16{
	0x001d, // x25519
	0x0017, // secp256r1
	0x0018, // secp384r1
	0x0019, // secp521r1
}

func extensions(serverName string) []byte {
	var out []byte
	add := func(kind uint16, data []byte) {
		out = binary.BigEndian.AppendUint16(out, kind)
		out = binary.BigEndian.AppendUint16(out, u16(len(data)))
		out = append(out, data...)
	}

	if name := hostName(serverName); name != "" {
		entry := []byte{0} // host_name
		entry = binary.BigEndian.AppendUint16(entry, u16(len(name)))
		entry = append(entry, name...)

		list := binary.BigEndian.AppendUint16(nil, u16(len(entry)))
		add(0x0000, append(list, entry...))
	}

	add(0x000a, uint16List(groups))
	add(0x000b, []byte{1, 0}) // ec_point_formats: uncompressed
	add(0x000d, uint16List(signatureAlgorithms))
	return out
}

// hostName returns what may be sent as a server name, or nothing.
//
// An address is not a name (RFC 6066), and a string carrying anything a
// hostname cannot is not sent at all. The target reaching here has already been
// checked by the scanner; this is the second lock, on the one path that writes
// it into bytes by hand.
func hostName(name string) string {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > maxServerName || net.ParseIP(name) != nil {
		return ""
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return ""
		}
	}
	return name
}

func uint16List(values []uint16) []byte {
	out := binary.BigEndian.AppendUint16(nil, u16(2*len(values)))
	for _, v := range values {
		out = binary.BigEndian.AppendUint16(out, v)
	}
	return out
}

// u16 encodes a length that has already been bounded.
//
// Every caller passes something bounded by a constant in this file — at most a
// hundred and twenty-eight suites, a name of 253 bytes, a fixed extension list —
// so the check cannot fail. It is here so that a later change that removes one
// of those bounds fails loudly in a test rather than writing a length that
// wrapped.
func u16(n int) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic("rawhello: a length was not bounded before it was encoded")
	}
	return uint16(n) // #nosec G115 -- checked on the line above
}

// Ask sends a hello over a connection that is already open and reads the answer.
//
// The connection is the caller's, so the guard on where it goes is the
// caller's too — and a caller in this project dials through safedial. The
// context bounds the whole exchange: a server that accepts the connection and
// then says nothing is given until the deadline and not a moment longer.
func Ask(ctx context.Context, conn net.Conn, h Hello) Result {
	hello, err := h.Marshal()
	if err != nil {
		return Result{Answer: Unanswered, Err: err}
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if _, err := conn.Write(hello); err != nil {
		return Result{Answer: Unanswered, Err: err}
	}
	return ReadReply(conn)
}

// ReadReply reads the first record of a server's answer and nothing more.
//
// At most the record header, a handshake header, the fixed part of a
// ServerHello, a session id of the permitted length, and a suite: seventy-eight
// bytes. A reply that claims to be longer is not read further, and one whose
// lengths do not add up is not believed.
func ReadReply(r io.Reader) Result {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Result{Answer: Unanswered, Err: err}
	}

	// Every SSL 3.0 and TLS record version begins with 3. Anything else is
	// something that is not this protocol — an HTTP error page, most often.
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if header[1] != 3 || length == 0 || length > maxRecord {
		return Result{Answer: Unanswered, Err: ErrNotTLS}
	}

	switch header[0] {
	case contentAlert:
		if length < 2 {
			return Result{Answer: Unanswered, Err: ErrNotTLS}
		}
		var alert [2]byte
		if _, err := io.ReadFull(r, alert[:]); err != nil {
			return Result{Answer: Unanswered, Err: err}
		}
		if alert[0] != alertFatal {
			// A warning is not a decision to decline. close_notify arrives
			// this way, and treating it as a refusal would record a server
			// hanging up as a server saying no.
			return Result{Answer: Unanswered, Err: errNotAnswerAlert}
		}
		return Result{Answer: Refused, Alert: alert[1]}

	case contentHandshake:
		return readServerHello(io.LimitReader(r, int64(length)), length)

	default:
		return Result{Answer: Unanswered, Err: ErrNotTLS}
	}
}

func readServerHello(r io.Reader, recordLength int) Result {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Result{Answer: Unanswered, Err: ErrSplit}
	}
	if header[0] != typeServerHello {
		return Result{Answer: Unanswered, Err: ErrNotServerHello}
	}

	messageLength := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if messageLength < serverHelloFixed+2 {
		return Result{Answer: Unanswered, Err: ErrNotServerHello}
	}

	var fixed [serverHelloFixed]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return Result{Answer: Unanswered, Err: ErrSplit}
	}

	sessionID := int(fixed[serverHelloFixed-1])
	switch {
	case sessionID > maxSessionID, messageLength < serverHelloFixed+sessionID+2:
		return Result{Answer: Unanswered, Err: ErrNotServerHello}
	case recordLength < 4+serverHelloFixed+sessionID+2:
		// The message goes on into a second record. Legal, rare, and not
		// followed: reassembling records is the start of implementing TLS,
		// and a guess at a suite from half a message is worse than no answer.
		//
		// This check and the io.LimitReader ReadReply wraps around this
		// function are one guard written twice, and a sabotage removing either
		// one alone escaped every test on 2026-09-13. That is not a missing
		// test: without this line the limited reader runs dry at the end of
		// the record and the read below fails the same way; without the limit,
		// this line has already refused before anything past the record is
		// read. Both are kept on purpose — this one names the reason, the
		// limit bounds the bytes whatever a later change does here — and
		// TestAServerHelloSplitAcrossRecordsIsNotGuessed fails the moment both
		// are gone.
		return Result{Answer: Unanswered, Err: ErrSplit}
	}

	if _, err := io.CopyN(io.Discard, r, int64(sessionID)); err != nil {
		return Result{Answer: Unanswered, Err: ErrSplit}
	}

	var suite [2]byte
	if _, err := io.ReadFull(r, suite[:]); err != nil {
		return Result{Answer: Unanswered, Err: ErrSplit}
	}

	return Result{
		Answer:  Accepted,
		Version: binary.BigEndian.Uint16(fixed[0:2]),
		Suite:   binary.BigEndian.Uint16(suite[:]),
	}
}
