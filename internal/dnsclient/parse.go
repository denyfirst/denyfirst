package dnsclient

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// parseReply reads a reply and checks it answers the question that was asked.
//
// Every length in what follows was chosen by whoever sent the message, and on
// a plaintext UDP path that is anyone who answered first. Each is therefore
// checked against what is actually left rather than trusted, and a length that
// does not fit ends the parse. Clamping a bad length to fit is how a parser is
// made to read one field as another.
//
// The checks before any record is read matter more than the record parsing.
// A reply that fails them was written by something that did not see the query,
// and reading its contents at all would be reading an attacker's answer.
func parseReply(raw []byte, id uint16, question []byte, qtype uint16) (reply, error) {
	if len(raw) < headerLen {
		return reply{}, errors.New("dnsclient: the reply is shorter than a header")
	}

	const (
		flagResponse    = 0x8000
		maskOpcode      = 0x7800
		flagAuthentic   = 0x0020
		maskRcode       = 0x000F
		rcodeNoError    = 0
		rcodeServerFail = 2
		rcodeNXDomain   = 3
		rcodeRefused    = 5
	)

	if got := binary.BigEndian.Uint16(raw[0:2]); got != id {
		return reply{}, fmt.Errorf("dnsclient: the reply answers query %d, not %d", got, id)
	}

	flags := binary.BigEndian.Uint16(raw[2:4])
	if flags&flagResponse == 0 {
		return reply{}, errors.New("dnsclient: the reply is not marked as one")
	}
	if flags&maskOpcode != 0 {
		return reply{}, errors.New("dnsclient: the reply is to a different kind of query")
	}

	if binary.BigEndian.Uint16(raw[4:6]) != 1 {
		return reply{}, errors.New("dnsclient: the reply does not carry exactly one question")
	}

	// The question, byte for byte. This is what the randomised case in the
	// query is for: a forger who did not see the request cannot reproduce it.
	wantQuestion := make([]byte, 0, len(question)+4)
	wantQuestion = append(wantQuestion, question...)
	wantQuestion = binary.BigEndian.AppendUint16(wantQuestion, qtype)
	wantQuestion = binary.BigEndian.AppendUint16(wantQuestion, classIN)

	end := headerLen + len(wantQuestion)
	if len(raw) < end || !bytes.Equal(raw[headerLen:end], wantQuestion) {
		return reply{}, errors.New("dnsclient: the reply echoes a different question")
	}

	out := reply{
		validated: flags&flagAuthentic != 0,
		existed:   true,
	}

	switch rcode := flags & maskRcode; rcode {
	case rcodeNoError:
	case rcodeNXDomain:
		out.existed = false
		return out, nil
	case rcodeServerFail:
		// Among other things, this is what a validating resolver returns when
		// DNSSEC does not check out. It is a refusal to answer rather than an
		// answer of none, and reporting it as the second would turn a broken
		// chain into a clean result.
		return out, ErrServerFail
	case rcodeRefused:
		return out, ErrRefused
	default:
		return out, fmt.Errorf("dnsclient: the resolver answered with code %d", rcode)
	}

	answers := int(binary.BigEndian.Uint16(raw[6:8]))
	found, err := parseAnswers(raw, end, answers, qtype, foldName(question))
	if err != nil {
		return out, err
	}
	out.records = found.caa
	out.txt = found.txt
	out.mx = found.mx
	out.tlsa = found.tlsa
	return out, nil
}

// parseAnswers reads the answer section, keeping only the records that answer
// the question that was asked.
//
// The owner name is checked rather than assumed, and that check is the point
// of the wantName argument. Everything above establishes that the message came
// from something that saw the query; none of it establishes that the records
// inside describe the name the query was about. A resolver — hostile, broken,
// or merely expanding a CNAME this client does not follow — can put a record
// set belonging to some other name here, and without this the report would
// present that other name's policy as this one's: "issuance limited to X (from
// example.com)" about a record that governs nothing of the sort.
//
// A record for another name is skipped rather than treated as an error, which
// is how RRSIG and every other type in the section are already handled. The
// walk then reports no CAA at this name and carries on to the parent, which is
// the honest answer: nothing was found for the name that was asked about.
func parseAnswers(raw []byte, offset, count int, qtype uint16, wantName []byte) (answerSet, error) {
	var out answerSet

	for i := 0; i < count; i++ {
		owner, next, err := readName(raw, offset)
		if err != nil {
			return answerSet{}, err
		}
		offset = next

		// Type, class, TTL, and the length of what follows: ten bytes before
		// anything variable.
		if offset+10 > len(raw) {
			return answerSet{}, errors.New("dnsclient: a record ends before its header does")
		}
		rrType := binary.BigEndian.Uint16(raw[offset : offset+2])
		rdLength := int(binary.BigEndian.Uint16(raw[offset+8 : offset+10]))
		offset += 10

		if rdLength < 0 || offset+rdLength > len(raw) {
			return answerSet{}, errors.New("dnsclient: a record announces more data than the reply holds")
		}
		rdata := raw[offset : offset+rdLength]

		// Where this record's data begins in the whole message. A name inside
		// it may be compressed — a pointer back into the message — so a parser
		// handed only the record's own bytes could not follow one.
		rdataAt := offset
		offset += rdLength

		// Anything else in the section is skipped rather than refused: a
		// reply carrying RRSIG alongside the records asked for is what asking
		// for DNSSEC produces, and treating it as a fault would reject every
		// signed zone. A record for another owner is skipped for the same
		// reason and with more cause: it answers a question nobody asked.
		if rrType != qtype || !bytes.Equal(owner, wantName) {
			continue
		}

		switch qtype {
		case TypeCAA:
			record, err := parseCAA(rdata)
			if err != nil {
				return answerSet{}, err
			}
			out.caa = append(out.caa, record)
		case TypeTXT:
			value, err := parseTXT(rdata)
			if err != nil {
				return answerSet{}, err
			}
			out.txt = append(out.txt, value)
		case TypeMX:
			record, err := parseMX(raw, rdata, rdataAt)
			if err != nil {
				return answerSet{}, err
			}
			out.mx = append(out.mx, record)
		case TypeTLSA:
			record, err := parseTLSA(rdata)
			if err != nil {
				return answerSet{}, err
			}
			out.tlsa = append(out.tlsa, record)
		}
	}

	return out, nil
}

// answerSet is what one answer section held, sorted by type.
//
// A struct rather than a growing list of return values: this returned two
// slices and an error while there were two record types, and a fourth type
// would have made every call site read a signature to find out which position
// meant what.
type answerSet struct {
	caa  []CAA
	txt  []string
	mx   []MX
	tlsa []TLSA
}

// parseCAA reads one property: a flags octet, a length-prefixed tag, and the
// value, which runs to the end of the record.
func parseCAA(rdata []byte) (CAA, error) {
	if len(rdata) < 2 {
		return CAA{}, errors.New("dnsclient: a CAA record is shorter than its own header")
	}

	tagLen := int(rdata[1])
	if tagLen == 0 || 2+tagLen > len(rdata) {
		return CAA{}, fmt.Errorf("dnsclient: a CAA tag announces %d bytes", tagLen)
	}

	tag := string(rdata[2 : 2+tagLen])
	if !printableASCII(tag) {
		return CAA{}, errors.New("dnsclient: a CAA tag is not printable")
	}

	value := string(rdata[2+tagLen:])
	if !printableASCII(value) {
		// The zone chooses this text and a hostile target chooses the zone.
		// A refusal here is reported as a malformed record, which is more
		// useful to a reader than the same bytes rendered somewhere.
		return CAA{}, errors.New("dnsclient: a CAA value is not printable")
	}

	const criticalBit = 0x80
	return CAA{
		Critical: rdata[0]&criticalBit != 0,
		Tag:      tag,
		Value:    value,
	}, nil
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// skipName walks past a name and returns where it ends.
//
// A wrapper rather than a second walker. Two functions that both have to get
// compression pointers right are two chances to get them wrong, and the one
// nobody is fuzzing is the one that will be wrong.
func skipName(raw []byte, offset int) (int, error) {
	_, next, err := readName(raw, offset)
	return next, err
}

// readName walks a name and returns both the name and where the record
// continues.
//
// The name comes back canonical: uncompressed, and with A-Z folded to
// lowercase. DNS comparison is case-insensitive, and a name written out in
// full and the same name written as a pointer are the same name, so anything
// comparing owner names has to compare this form rather than the bytes as they
// arrived. It is also what makes the randomised case in the query harmless
// here: the reply echoes the question with its case intact, and folding is
// what lets that name still match a record's owner.
//
// Names are compressed: a label may be replaced by a pointer to an earlier
// one, which is how a reply repeating the same domain a dozen times stays
// small. It is also the oldest way to make a DNS parser loop forever, by
// pointing a name at itself.
//
// Two rules close that. A pointer must go backwards, so a chain of them
// strictly decreases and cannot return to where it started; and the number
// followed is capped, so a chain descending one byte at a time through a long
// reply still ends. Either alone would do. Both are here because this is the
// bug every hand-written DNS parser has had at least once.
func readName(raw []byte, offset int) (name []byte, next int, err error) {
	const (
		pointerMask  = 0xC0
		pointerValue = 0xC0
	)

	start := offset
	pointers := 0
	length := 0
	name = make([]byte, 0, 32)

	for {
		if offset >= len(raw) {
			return nil, 0, errors.New("dnsclient: a name runs past the end of the reply")
		}

		size := int(raw[offset])

		switch {
		case size == 0:
			// The root label ends the name. If a pointer was followed, the
			// name in the record ended at the pointer rather than here.
			name = append(name, 0)
			if pointers > 0 {
				return name, start, nil
			}
			return name, offset + 1, nil

		case size&pointerMask == pointerValue:
			if offset+2 > len(raw) {
				return nil, 0, errors.New("dnsclient: a compression pointer is cut short")
			}
			target := int(binary.BigEndian.Uint16(raw[offset:offset+2]) &^ 0xC000)

			if target >= offset {
				return nil, 0, errors.New("dnsclient: a compression pointer does not point backwards")
			}
			pointers++
			if pointers > maxPointers {
				return nil, 0, errors.New("dnsclient: too many compression pointers")
			}
			if pointers == 1 {
				start = offset + 2
			}
			offset = target

		case size <= maxLabel:
			length += size + 1
			if length > maxName {
				return nil, 0, errors.New("dnsclient: a name is longer than a name may be")
			}
			if offset+1+size > len(raw) {
				return nil, 0, errors.New("dnsclient: a label runs past the end of the reply")
			}
			name = append(name, byte(size))
			name = appendFolded(name, raw[offset+1:offset+1+size])
			offset += 1 + size

		default:
			return nil, 0, fmt.Errorf("dnsclient: a label length byte is %#x", size)
		}
	}
}

// foldName returns a wire-form name with A-Z folded to lowercase.
//
// One pass over the whole buffer, length bytes included, and that is safe
// rather than sloppy: a label is at most 63 bytes, so a length byte can never
// hold a value in the letter range. A byte-wise fold rather than
// bytes.ToLower, because a label carries arbitrary bytes and a UTF-8 aware
// fold would rewrite the ones that are not valid text.
func foldName(name []byte) []byte {
	return appendFolded(make([]byte, 0, len(name)), name)
}

func appendFolded(dst, src []byte) []byte {
	for _, b := range src {
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		dst = append(dst, b)
	}
	return dst
}

// parseTXT joins the character-strings a TXT record is made of.
//
// A TXT record is one or more length-prefixed strings, each at most 255 bytes,
// and a value longer than that arrives split across several. Joining them with
// nothing between is what every consumer of a DNS-published token does — ACME
// among them — because the split is a wire format detail and not part of the
// value somebody published.
//
// Records are kept separate from each other. A name can carry several TXT
// records for unrelated purposes, and concatenating those would invent a value
// nobody wrote.
func parseTXT(rdata []byte) (string, error) {
	var b strings.Builder

	for i := 0; i < len(rdata); {
		n := int(rdata[i])
		i++
		if i+n > len(rdata) {
			return "", errors.New("dnsclient: a TXT string runs past the end of its record")
		}
		b.Write(rdata[i : i+n])
		i += n
	}

	return b.String(), nil
}

// parseMX reads one mail exchanger: a preference and a name.
//
// The name is read through readName rather than sliced out, because a name in
// an answer may be compressed — a pointer back into the message — and a parser
// that treated the bytes literally would produce a host nobody can resolve out
// of a reply that is perfectly ordinary.
func parseMX(raw, rdata []byte, rdataAt int) (MX, error) {
	if len(rdata) < 3 {
		return MX{}, errors.New("dnsclient: an MX record is shorter than its own header")
	}

	// Read through readName, from the position in the whole message, because
	// the name may be compressed. A parser that sliced the bytes literally
	// would produce a host nobody can resolve out of a reply that is perfectly
	// ordinary — and most real answers compress this name.
	host, _, err := readName(raw, rdataAt+2)
	if err != nil {
		return MX{}, err
	}

	return MX{
		Preference: binary.BigEndian.Uint16(rdata[0:2]),
		Host:       nameText(host),
	}, nil
}

// parseTLSA reads one DANE record's three selectors.
//
// The certificate association data itself is deliberately not kept. This
// project reports that a domain publishes DANE and what kind of binding it
// declares; checking the binding means holding a certificate from the mail
// host, which needs a connection to it, and the mail check makes none (N13).
func parseTLSA(rdata []byte) (TLSA, error) {
	if len(rdata) < 4 {
		return TLSA{}, errors.New("dnsclient: a TLSA record is shorter than its own header")
	}
	return TLSA{
		Usage:    rdata[0],
		Selector: rdata[1],
		Matching: rdata[2],
	}, nil
}

// nameText turns a name in wire form into text a report can carry.
//
// The value comes from a resolver, which N5 treats as hostile, so it is
// bounded, stripped of anything that is not an ordinary name character, and
// lowercased for comparison (I7). A host name that reached a terminal report
// carrying a newline would forge a line in it.
//
// The root — a single zero byte — comes back as "." rather than as an empty
// string. A domain publishing MX "." is making RFC 7505's statement that it
// accepts no mail at all, and an empty field would read as a record nobody
// could parse instead of as the declaration it is.
func nameText(encoded []byte) string {
	var parts []string
	for i := 0; i < len(encoded); {
		size := int(encoded[i])
		if size == 0 || i+1+size > len(encoded) {
			break
		}
		parts = append(parts, string(encoded[i+1:i+1+size]))
		i += 1 + size
	}

	name := strings.ToLower(strings.Join(parts, "."))
	if name == "" {
		return "."
	}
	if len(name) > maxNameLength {
		name = name[:maxNameLength]
	}

	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '-' || r == '_':
			return r
		}
		return -1
	}, name)
}

// maxNameLength is the longest name RFC 1035 allows, and the bound on anything
// a resolver hands back.
const maxNameLength = 253
