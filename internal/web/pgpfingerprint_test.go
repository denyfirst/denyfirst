package web

import (
	// #nosec G505 -- SHA-1 is not a security choice here. An OpenPGP version 4
	// fingerprint is defined as SHA-1 over the public key packet, so computing
	// one with anything else would compute a different number. Nothing is
	// signed, verified or protected with this; it is read back and compared
	// against a constant.
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// The published fingerprint is now derived from the bytes this server sends.
//
// D1's test compared the fingerprint against its two published copies and
// never looked at the key. A key file swapped for another, leaving both
// copies alone, passed every check in this repository — and that is the whole
// attack the fingerprint exists to stop: a reporter who fetches the key from
// this domain, compares its fingerprint against SECURITY.md on GitHub, and
// encrypts an unpublished vulnerability to whatever was actually served.
//
// The gap was listed as needing "an OpenPGP parser and SHA-1". It needs the
// first packet of one. A version 4 fingerprint is SHA-1 over 0x99, the
// packet's length as two bytes, and the packet body, which is sixty lines of
// standard library and no dependency at all.
func TestTheServedKeyIsTheKeyWePublish(t *testing.T) {
	served := get(t, PGPKeyPath).Body.String()

	packets := armoredBody(t, served)
	got := primaryKeyFingerprint(t, packets)

	if got != PGPFingerprint {
		t.Fatalf("the key served at %s has fingerprint\n  %s\nand this repository publishes\n  %s\n"+
			"A reporter comparing the two would encrypt to the wrong key.", PGPKeyPath, got, PGPFingerprint)
	}
}

// armoredBody returns the binary packets inside an ASCII-armoured block, and
// fails if the armour's own checksum does not cover them.
//
// The checksum is checked because it is the half that catches a truncated
// file. A key cut short parses into a shorter packet, hashes to a different
// fingerprint, and would fail the test above with a message about the wrong
// key rather than about a damaged file.
func armoredBody(t *testing.T, text string) []byte {
	t.Helper()

	const begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	const end = "-----END PGP PUBLIC KEY BLOCK-----"

	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")

	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == begin {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("the served file has no armour header")
	}

	// Armour headers run until the first blank line.
	i := start + 1
	for i < len(lines) && strings.TrimSpace(lines[i]) != "" {
		i++
	}
	i++

	var (
		body     strings.Builder
		checksum string
		closed   bool
	)
	for ; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		switch {
		case line == end:
			closed = true
		case strings.HasPrefix(line, "="):
			checksum = line[1:]
		default:
			body.WriteString(line)
		}
		if closed {
			break
		}
	}
	if !closed {
		t.Fatal("the served file opens an armour block that is never closed")
	}
	if checksum == "" {
		t.Fatal("the served file carries no armour checksum, so a truncated key would go unnoticed")
	}

	packets, err := base64.StdEncoding.DecodeString(body.String())
	if err != nil {
		t.Fatalf("decoding the armoured key: %v", err)
	}

	// Four base64 characters, which is exactly three bytes and no padding.
	if len(checksum) != 4 {
		t.Fatalf("the armour checksum %q is %d characters, want 4", checksum, len(checksum))
	}
	raw, err := base64.StdEncoding.DecodeString(checksum)
	if err != nil || len(raw) != 3 {
		t.Fatalf("the armour checksum %q could not be read: %v", checksum, err)
	}
	want := uint32(raw[0])<<16 | uint32(raw[1])<<8 | uint32(raw[2])

	if got := crc24(packets); got != want {
		t.Fatalf("the armour checksum is %06x and the key hashes to %06x; the served file is damaged", want, got)
	}
	return packets
}

// crc24 is the checksum RFC 9580 puts at the end of an armoured block.
func crc24(data []byte) uint32 {
	const (
		init = 0xB704CE
		poly = 0x1864CFB
	)
	crc := uint32(init)
	for _, b := range data {
		crc ^= uint32(b) << 16
		for range 8 {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= poly
			}
		}
	}
	return crc & 0xFFFFFF
}

// primaryKeyFingerprint reads the first packet and returns its version 4
// fingerprint.
//
// Only the first packet is read, and it has to be a public key. Everything
// after it — user identifiers, signatures, subkeys — has no bearing on the
// primary key's fingerprint, and a parser that walked them would be a parser
// with more to get wrong.
func primaryKeyFingerprint(t *testing.T, packets []byte) string {
	t.Helper()

	if len(packets) < 3 {
		t.Fatal("the armoured block holds no packet")
	}

	header := packets[0]
	if header&0x80 == 0 {
		t.Fatalf("the first byte %#02x is not an OpenPGP packet header", header)
	}

	var (
		tag    int
		length int
		offset int
	)

	if header&0x40 != 0 {
		// New format: the tag is six bits and the length is self-describing.
		tag = int(header & 0x3F)
		switch first := packets[1]; {
		case first < 192:
			length, offset = int(first), 2
		case first < 224:
			if len(packets) < 3 {
				t.Fatal("the packet announces a two-byte length it does not carry")
			}
			length, offset = (int(first-192)<<8)+int(packets[2])+192, 3
		case first == 255:
			if len(packets) < 6 {
				t.Fatal("the packet announces a five-byte length it does not carry")
			}
			length, offset = int(binary.BigEndian.Uint32(packets[2:6])), 6
		default:
			t.Fatal("the public key packet is split into partial lengths, which an exported key is not")
		}
	} else {
		// Old format: the tag is four bits and two bits choose the length's
		// own width. This is the form gpg exports today.
		tag = int(header>>2) & 0x0F
		switch header & 0x03 {
		case 0:
			length, offset = int(packets[1]), 2
		case 1:
			if len(packets) < 4 {
				t.Fatal("the packet announces a two-byte length it does not carry")
			}
			length, offset = int(binary.BigEndian.Uint16(packets[1:3])), 3
		case 2:
			if len(packets) < 6 {
				t.Fatal("the packet announces a four-byte length it does not carry")
			}
			length, offset = int(binary.BigEndian.Uint32(packets[1:5])), 5
		default:
			t.Fatal("the first packet has an indeterminate length, which a public key does not")
		}
	}

	const publicKey = 6
	if tag != publicKey {
		t.Fatalf("the first packet has tag %d, want %d; the served file does not begin with a public key", tag, publicKey)
	}
	if length <= 0 || offset+length > len(packets) {
		t.Fatalf("the public key packet announces %d bytes and the block holds %d", length, len(packets)-offset)
	}

	body := packets[offset : offset+length]
	if body[0] != 4 {
		t.Fatalf("the key is version %d; this computes a version 4 fingerprint and would report a wrong number for any other",
			body[0])
	}

	// RFC 9580: SHA-1 over 0x99, the two-byte packet length, and the body.
	prefix := []byte{0x99, byte(length >> 8), byte(length)}
	// #nosec G401 -- the definition of a version 4 fingerprint, not a choice.
	sum := sha1.Sum(append(prefix, body...))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// A private key in the served file is the worst outcome available here, and
// the packet tag says so without any string matching.
func TestTheServedPacketIsAPublicKeyPacket(t *testing.T) {
	packets := armoredBody(t, get(t, PGPKeyPath).Body.String())

	if tag := int(packets[0]>>2) & 0x0F; tag == 5 || tag == 7 {
		t.Fatalf("the served file begins with packet tag %d, which is a secret key", tag)
	}
}
