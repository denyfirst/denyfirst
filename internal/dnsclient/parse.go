package dnsclient

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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
	records, err := parseAnswers(raw, end, answers, qtype)
	if err != nil {
		return out, err
	}
	out.records = records
	return out, nil
}

func parseAnswers(raw []byte, offset, count int, qtype uint16) ([]CAA, error) {
	var out []CAA

	for i := 0; i < count; i++ {
		next, err := skipName(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next

		// Type, class, TTL, and the length of what follows: ten bytes before
		// anything variable.
		if offset+10 > len(raw) {
			return nil, errors.New("dnsclient: a record ends before its header does")
		}
		rrType := binary.BigEndian.Uint16(raw[offset : offset+2])
		rdLength := int(binary.BigEndian.Uint16(raw[offset+8 : offset+10]))
		offset += 10

		if rdLength < 0 || offset+rdLength > len(raw) {
			return nil, errors.New("dnsclient: a record announces more data than the reply holds")
		}
		rdata := raw[offset : offset+rdLength]
		offset += rdLength

		// Anything else in the section is skipped rather than refused: a
		// reply carrying RRSIG alongside the records asked for is what asking
		// for DNSSEC produces, and treating it as a fault would reject every
		// signed zone.
		if rrType != qtype || qtype != TypeCAA {
			continue
		}

		record, err := parseCAA(rdata)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}

	return out, nil
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
func skipName(raw []byte, offset int) (int, error) {
	const (
		pointerMask  = 0xC0
		pointerValue = 0xC0
	)

	start := offset
	pointers := 0
	length := 0

	for {
		if offset >= len(raw) {
			return 0, errors.New("dnsclient: a name runs past the end of the reply")
		}

		size := int(raw[offset])

		switch {
		case size == 0:
			// The root label ends the name. If a pointer was followed, the
			// name in the record ended at the pointer rather than here.
			if pointers > 0 {
				return start, nil
			}
			return offset + 1, nil

		case size&pointerMask == pointerValue:
			if offset+2 > len(raw) {
				return 0, errors.New("dnsclient: a compression pointer is cut short")
			}
			target := int(binary.BigEndian.Uint16(raw[offset:offset+2]) &^ 0xC000)

			if target >= offset {
				return 0, errors.New("dnsclient: a compression pointer does not point backwards")
			}
			pointers++
			if pointers > maxPointers {
				return 0, errors.New("dnsclient: too many compression pointers")
			}
			if pointers == 1 {
				start = offset + 2
			}
			offset = target

		case size <= maxLabel:
			length += size + 1
			if length > maxName {
				return 0, errors.New("dnsclient: a name is longer than a name may be")
			}
			if offset+1+size > len(raw) {
				return 0, errors.New("dnsclient: a label runs past the end of the reply")
			}
			offset += 1 + size

		default:
			return 0, fmt.Errorf("dnsclient: a label length byte is %#x", size)
		}
	}
}
