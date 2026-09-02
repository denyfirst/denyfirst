package certinfo

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
)

// Attribute types this test builds names from.
var (
	oidBusinessCategory       = asn1.ObjectIdentifier{2, 5, 4, 15}
	oidJurisdictionCountry    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}
	oidJurisdictionState      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2}
	oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	oidUnknownToEveryone      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7, 1}
)

// A name of nothing but attributes Go names renders exactly as it always did.
//
// This is the whole safety of the change. Every certificate this project has
// ever described carries only these attributes, so if the two renderings
// differ here then a rendering fix has quietly altered what thousands of
// ordinary reports say — and the reason to write this was hex on a handful of
// EV certificates, not a new format for everybody.
func TestAnOrdinaryNameRendersExactlyAsItDidBefore(t *testing.T) {
	for _, name := range []pkix.Name{
		{CommonName: "example.test"},
		{
			CommonName:   "*.kapitalbank.az",
			Organization: []string{"Kapital Bank, ASC"},
			Locality:     []string{"Baku"},
			Country:      []string{"AZ"},
		},
		{
			CommonName:         "mail.example.test",
			Organization:       []string{`A "quoted" name`},
			OrganizationalUnit: []string{"IT", "Security"},
			Province:           []string{"Some+Province"},
			PostalCode:         []string{"AZ1000"},
			StreetAddress:      []string{"1 Example Street"},
			SerialNumber:       "C1234567",
		},
		// Empty, which is a certificate a server can serve.
		{},
	} {
		if got, want := distinguishedName(name), name.String(); got != want {
			t.Errorf("an ordinary name renders differently now:\n  before %q\n   after %q", want, got)
		}
	}
}

// The attributes extended validation exists to carry are readable.
//
// Before this, all three of them reached the reader as the dotted identifier
// and the DER bytes in hexadecimal — the business category and the
// jurisdiction of incorporation, which are the only things an EV certificate
// claims that an organisation-validated one does not.
func TestAnExtendedValidationNameIsReadable(t *testing.T) {
	name := pkix.Name{
		CommonName:   "www.example-bank.test",
		Organization: []string{"Example Bank, Inc."},
		Country:      []string{"US"},
		SerialNumber: "C1234567",
		Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Example Bank, Inc."},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "www.example-bank.test"},
			{Type: oidBusinessCategory, Value: "Private Organization"},
			{Type: oidJurisdictionCountry, Value: "US"},
			{Type: oidJurisdictionState, Value: "Delaware"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 5}, Value: "C1234567"},
		},
	}

	got := distinguishedName(name)

	for _, want := range []string{
		"businessCategory=Private Organization",
		"jurisdictionC=US",
		"jurisdictionST=Delaware",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the name does not carry %q:\n  %s", want, got)
		}
	}
	if strings.Contains(got, "#13") {
		t.Errorf("part of the name is still DER in hexadecimal:\n  %s", got)
	}
	if strings.Contains(got, "1.3.6.1.4.1.311.60.2.1") {
		t.Errorf("a jurisdiction attribute is still shown as an identifier:\n  %s", got)
	}
}

// An identifier nobody here recognises keeps its identifier and loses the hex.
//
// Naming it would be inventing a meaning. Showing the value is not: the value
// is what the certificate says, and a reader who knows the identifier can now
// read it while one who does not is no worse off than before.
func TestAnUnknownAttributeKeepsItsIdentifierAndShowsItsValue(t *testing.T) {
	name := pkix.Name{
		CommonName: "example.test",
		Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "example.test"},
			{Type: oidUnknownToEveryone, Value: "something a reader can see"},
		},
	}

	got := distinguishedName(name)
	if !strings.Contains(got, "1.3.6.1.4.1.99999.7.1=something a reader can see") {
		t.Errorf("an unknown attribute does not show its value:\n  %s", got)
	}
}

// A value that is not text keeps the hexadecimal form.
//
// This report cannot read the bytes, and a rendering that guessed at them
// would be a measurement nobody made. The hex is honest; it says here are the
// bytes, make of them what you will.
func TestAValueThatIsNotTextStaysHexadecimal(t *testing.T) {
	name := pkix.Name{
		CommonName: "example.test",
		Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "example.test"},
			{Type: oidOrganizationIdentifier, Value: []byte{0x01, 0x02, 0x03}},
		},
	}

	got := distinguishedName(name)
	if !strings.Contains(got, "organizationIdentifier=#") {
		t.Errorf("a value that could not be read as text was rendered as though it had been:\n  %s", got)
	}
}

// The grammar of a name is still escaped.
//
// A comma inside a value is what separates two attributes outside one, so a
// value carrying one has to be escaped or the name a reader sees is not the
// name the certificate holds. This is Go's rule and RFC 4514's, and the
// rewrite has to keep it — an organisation called "Bank, Inc." is ordinary.
func TestAValueThatLooksLikeTheGrammarIsEscaped(t *testing.T) {
	for _, c := range []struct {
		value string
		want  string
	}{
		{"Bank, Inc.", `Bank\, Inc.`},
		{"a+b", `a\+b`},
		{`say "hello"`, `say \"hello\"`},
		{`back\slash`, `back\\slash`},
		{"<angle>", `\<angle\>`},
		{"semi;colon", `semi\;colon`},
		{" leading", `\ leading`},
		{"trailing ", `trailing\ `},
		{"#leading", `\#leading`},
		{"not#leading", "not#leading"},
	} {
		name := pkix.Name{Names: []pkix.AttributeTypeAndValue{
			{Type: oidUnknownToEveryone, Value: c.value},
		}}
		if got := distinguishedName(name); !strings.Contains(got, c.want) {
			t.Errorf("value %q rendered as %q, which does not contain %q", c.value, got, c.want)
		}
	}
}

// And it reaches the report, through a real certificate.
//
// The unit tests above build a pkix.Name by hand. This one puts the
// attributes into a certificate, signs it, parses it back the way a handshake
// would, and reads the string the report carries — because between the
// renderer and the report sit describe and the sanitiser, and a fix that
// works in one function and not on the page is not a fix.
func TestAnExtendedValidationSubjectReachesTheReport(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{subject: &pkix.Name{
		CommonName:   "example.test",
		Organization: []string{"Example Bank, Inc."},
		Country:      []string{"US"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: oidBusinessCategory, Value: "Private Organization"},
			{Type: oidJurisdictionCountry, Value: "US"},
			{Type: oidJurisdictionState, Value: "Delaware"},
		},
	}})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if len(report.Chain) == 0 {
		t.Fatal("the report carries no certificate, so it says nothing about a subject")
	}

	subject := report.Chain[0].Subject
	for _, want := range []string{
		"businessCategory=Private Organization",
		"jurisdictionC=US",
		"jurisdictionST=Delaware",
		`O=Example Bank\, Inc.`,
	} {
		if !strings.Contains(subject, want) {
			t.Errorf("the subject on the report does not carry %q:\n  %s", want, subject)
		}
	}
	if strings.Contains(subject, "#13") {
		t.Errorf("the subject on the report is still part hexadecimal:\n  %s", subject)
	}

	// Once each. An attribute Go parsed into a named field is emitted by
	// ToRDNSequence, so copying it out of Names as well prints it twice.
	//
	// Counted over the labels rather than over the text. strings.Count of
	// "C=" finds the C in jurisdictionC and reports a duplicate that is not
	// there — which it did, on the first version of this check.
	seen := map[string]int{}
	for _, label := range attributeLabels(subject) {
		seen[label]++
	}
	for _, once := range []string{"CN", "O", "C", "businessCategory", "jurisdictionC", "jurisdictionST"} {
		if seen[once] != 1 {
			t.Errorf("%q appears %d times in the subject, not once:\n  %s", once, seen[once], subject)
		}
	}
}

// attributeLabels splits a rendered name into its attribute labels.
//
// A comma inside a value is escaped, so splitting on every comma would cut an
// organisation called "Bank, Inc." in half and report a label of " Inc.".
func attributeLabels(dn string) []string {
	var (
		out     []string
		current strings.Builder
		escaped bool
	)
	for _, r := range dn {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ',':
			out = append(out, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	out = append(out, current.String())

	for i, part := range out {
		if k := strings.Index(part, "="); k >= 0 {
			out[i] = part[:k]
		}
	}
	return out
}

// The same, on a name that came off the wire.
//
// The test above builds pkix.Name structs by hand, and a hand-built one has
// an empty Names field — so the loop that copies unparsed attributes has
// nothing to copy and the guard that stops it copying the parsed ones is
// never exercised. Removing that guard passed every test written before this
// one, while making a parsed subject print CN, O and C twice.
//
// A parsed certificate is the case that matters, because it is the only case
// this program ever sees. Go's own rendering is the oracle: for a name of
// ordinary attributes the two have to agree character for character, and a
// duplicate cannot hide inside a Contains.
func TestAParsedOrdinaryNameRendersExactlyAsItDidBefore(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{subject: &pkix.Name{
		CommonName:         "example.test",
		Organization:       []string{"Example, Inc."},
		OrganizationalUnit: []string{"IT"},
		Locality:           []string{"Baku"},
		Province:           []string{"Baku"},
		Country:            []string{"AZ"},
		PostalCode:         []string{"AZ1000"},
		StreetAddress:      []string{"1 Example Street"},
		SerialNumber:       "C1234567",
	}})

	if len(leaf.Subject.Names) == 0 {
		t.Fatal("the parsed subject carries no attributes, so this test cannot see a duplicate")
	}
	if got, want := distinguishedName(leaf.Subject), leaf.Subject.String(); got != want {
		t.Errorf("a parsed ordinary name renders differently now:\n  before %q\n   after %q", want, got)
	}
	if got, want := distinguishedName(leaf.Issuer), leaf.Issuer.String(); got != want {
		t.Errorf("a parsed issuer renders differently now:\n  before %q\n   after %q", want, got)
	}
}
