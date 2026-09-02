package certinfo

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"strings"
)

// A distinguished name a reader can read.
//
// Go renders an attribute type it has no name for as the dotted object
// identifier and the DER bytes in hexadecimal, so an extended-validation
// subject arrives as
//
//	1.3.6.1.4.1.311.60.2.1.2=#130844656c6177617265
//
// That hex carries the word "Delaware" and shows a reader none of it. Three
// attributes render that way on every EV certificate, and they are precisely
// the attributes extended validation exists to carry: the business category
// and the jurisdiction of incorporation. The one thing such a certificate
// claims over a cheaper one was the part this report could not display.
//
// Nothing had to be parsed to fix it. Go has already read the values —
// pkix.Name.Names holds every attribute with its value as text — and only the
// rendering throws them away. So the rendering is done here.
//
// The arrangement is Go's, deliberately: the same attribute order, the same
// separators, the same RFC 4514 escaping. A certificate carrying only
// attributes Go names renders byte-identically to what this project has
// always printed, which is checked by a test. What changes is the certificates
// where Go printed hex.

// attributeNames are the short forms this report prints.
//
// Go's own table stops at the nine attributes it parses into named fields.
// The rest are the ones that actually appear in certificates: the EV
// jurisdiction attributes, the organisation identifier that eIDAS and PSD2
// certificates carry, and the everyday ones a mail or client certificate has.
//
// An identifier not in here keeps its dotted form. That is honest — this
// report does not know what it is — and it is still an improvement, because
// the value beside it is now the text rather than the bytes.
var attributeNames = map[string]string{
	// Parsed by Go into named fields, named here so that one table renders
	// the whole name.
	"2.5.4.3":  "CN",
	"2.5.4.5":  "SERIALNUMBER",
	"2.5.4.6":  "C",
	"2.5.4.7":  "L",
	"2.5.4.8":  "ST",
	"2.5.4.9":  "STREET",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.17": "POSTALCODE",

	// What Go leaves as an identifier.
	"2.5.4.4":                    "SN",
	"2.5.4.12":                   "title",
	"2.5.4.15":                   "businessCategory",
	"2.5.4.42":                   "GN",
	"2.5.4.65":                   "pseudonym",
	"2.5.4.97":                   "organizationIdentifier",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "emailAddress",

	// Extended validation. The jurisdiction of incorporation is the claim
	// that separates an EV certificate from an organisation-validated one,
	// and all three arrived as hex.
	"1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL",
	"1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
	"1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
}

// distinguishedName renders a parsed name.
//
// The sequence is assembled exactly as Go assembles it — attributes it did
// not parse into a named field first, so that they print last — because the
// order a reader has been looking at for the life of this project is not
// worth changing to fix a rendering.
func distinguishedName(n pkix.Name) string {
	var rdns pkix.RDNSequence

	// ExtraNames is populated only by a caller building a name to write out.
	// Nothing here does that, but the check is Go's and costs a line: with
	// ExtraNames set, ToRDNSequence already carries everything.
	if len(n.ExtraNames) == 0 {
		for _, atv := range n.Names {
			if parsedIntoField(atv.Type) {
				continue
			}
			rdns = append(rdns, []pkix.AttributeTypeAndValue{atv})
		}
	}
	rdns = append(rdns, n.ToRDNSequence()...)

	var b strings.Builder
	for i := range rdns {
		if i > 0 {
			b.WriteString(",")
		}
		rdn := rdns[len(rdns)-1-i]
		for j, atv := range rdn {
			if j > 0 {
				b.WriteString("+")
			}
			b.WriteString(attributeName(atv.Type))
			b.WriteString("=")
			b.WriteString(attributeValue(atv.Value))
		}
	}
	return b.String()
}

// parsedIntoField reports whether Go put this attribute into a named field of
// pkix.Name, which means ToRDNSequence will emit it and emitting it here as
// well would print it twice.
func parsedIntoField(t asn1.ObjectIdentifier) bool {
	if len(t) != 4 || t[0] != 2 || t[1] != 5 || t[2] != 4 {
		return false
	}
	switch t[3] {
	case 3, 5, 6, 7, 8, 9, 10, 11, 17:
		return true
	}
	return false
}

func attributeName(t asn1.ObjectIdentifier) string {
	if name, ok := attributeNames[t.String()]; ok {
		return name
	}
	return t.String()
}

// attributeValue renders one value.
//
// A value Go parsed as text is printed as text, escaped the way RFC 4514
// requires. Anything else keeps the hexadecimal form: this report cannot read
// it, and a guess at what the bytes mean would be a measurement nobody made.
//
// Everything returned here is chosen by the server being examined and is put
// through sanitise by the caller, which is where R10 is enforced. The
// escaping below is about the grammar of a distinguished name, not about what
// a terminal will do with it, and the two must not be confused for each other.
func attributeValue(v any) string {
	text, ok := v.(string)
	if !ok {
		der, err := asn1.Marshal(v)
		if err != nil {
			// Neither text nor bytes that can be written down. Saying so
			// beats printing Go's rendering of an internal value.
			return "#unreadable"
		}
		return "#" + hex.EncodeToString(der)
	}

	var b strings.Builder
	for i, r := range text {
		escape := false
		switch r {
		case ',', '+', '"', '\\', '<', '>', ';':
			escape = true
		case ' ':
			escape = i == 0 || i == len(text)-1
		case '#':
			escape = i == 0
		}
		if escape {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
