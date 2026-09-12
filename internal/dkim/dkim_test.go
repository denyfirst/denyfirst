package dkim

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// zone answers from a table, so a report is checked against records this test
// wrote rather than against whatever the machine can reach.
type zone struct {
	records map[string][]string
	fail    map[string]error
	asked   []string
}

func (z *zone) LookupTXT(_ context.Context, name string) ([]string, bool, error) {
	name = strings.ToLower(name)
	z.asked = append(z.asked, name)

	if err := z.fail[name]; err != nil {
		return nil, false, err
	}
	values, ok := z.records[name]
	return values, ok, nil
}

// publicKey makes a real RSA key of a given size and returns it as a p= value.
func publicKey(t *testing.T, bits int) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generating a %d-bit key: %v", bits, err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// shortKey builds a p= value for a key too small for Go to generate.
//
// Go refuses to make an RSA key under 1024 bits, and rightly — but a DKIM
// record published in 2014 and never touched since carries exactly that, which
// is the case this whole size check exists for. Parsing one is not generating
// one, so the modulus is assembled directly.
func shortKey(t *testing.T, bits int) string {
	t.Helper()

	// A modulus of the right length. Its value is irrelevant: nothing here
	// verifies a signature, and what is being read is its size.
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))

	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatalf("marshalling a %d-bit key: %v", bits, err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// Nothing is looked under unless a selector was given.
//
// The whole shape of this package. DNS cannot list what is beneath a name, so
// there is no set of selectors to discover — and a check that invented one and
// then reported an absence would be reporting on names it chose itself.
func TestNothingIsLookedUnderWithoutASelector(t *testing.T) {
	z := &zone{records: map[string][]string{}}

	got := Check(context.Background(), z, "example.com", nil)
	if got.Looked {
		t.Error("a check with no selectors reports that it looked")
	}
	if len(z.asked) != 0 {
		t.Errorf("it asked anyway: %v", z.asked)
	}
}

// A key is read, and its size with it.
func TestAKeyIsReadWithItsSize(t *testing.T) {
	p := publicKey(t, 2048)
	z := &zone{records: map[string][]string{
		"s1._domainkey.example.com": {"v=DKIM1; k=rsa; p=" + p},
	}}

	got := Check(context.Background(), z, "example.com", Named("s1"))
	if len(got.Keys) != 1 {
		t.Fatalf("got %+v", got.Keys)
	}

	k := got.Keys[0]
	if !k.Found {
		t.Fatal("the key was not found")
	}
	if k.Bits != 2048 {
		t.Errorf("bits = %d, want 2048", k.Bits)
	}
	if k.Source != FromOperator {
		t.Errorf("source = %q, want %q", k.Source, FromOperator)
	}
	if k.Weak() {
		t.Error("a 2048-bit key was called weak")
	}
}

// A key below the floor RFC 8301 sets is one a verifier may treat as insecure.
//
// Not a threshold chosen here. RFC 8301 raised the floor to 1024 and says a
// verifier MAY treat anything shorter as insecure, so a key under it is one a
// receiver is entitled to ignore — a fact about the key rather than an opinion.
func TestAKeyBelowTheFloorIsWeak(t *testing.T) {
	small := shortKey(t, 512)
	z := &zone{records: map[string][]string{
		"s1._domainkey.example.com": {"v=DKIM1; k=rsa; p=" + small},
	}}

	got := Check(context.Background(), z, "example.com", Named("s1"))
	if len(got.Keys) != 1 {
		t.Fatalf("got %+v", got.Keys)
	}
	if got.Keys[0].Bits != 512 {
		t.Fatalf("bits = %d, want 512", got.Keys[0].Bits)
	}
	if !got.Keys[0].Weak() {
		t.Error("a 512-bit key is not called weak, and RFC 8301 says a verifier may ignore it")
	}

	// And the boundary is not itself weak: 1024 is the floor, not below it.
	exact := Key{Found: true, Bits: 1024}
	if exact.Weak() {
		t.Error("a key at the floor is called weak; RFC 8301 says at least 1024, not more than")
	}
}

// An empty p= is a revoked key, not a broken record.
//
// RFC 6376 defines it that way, and the difference is a decision against a
// mistake. Reading it as unparseable would tell an operator who deliberately
// revoked a key that their record is wrong.
func TestAnEmptyKeyIsRevokedRatherThanBroken(t *testing.T) {
	z := &zone{records: map[string][]string{
		"old._domainkey.example.com": {"v=DKIM1; k=rsa; p="},
	}}

	got := Check(context.Background(), z, "example.com", Named("old"))
	if len(got.Keys) != 1 {
		t.Fatalf("got %+v", got.Keys)
	}
	k := got.Keys[0]
	if !k.Found {
		t.Error("a revoked key was reported as no key at all")
	}
	if !k.Revoked {
		t.Error("an empty p= was not read as a revoked key")
	}
	if k.Weak() {
		t.Error("a revoked key was also called weak, which is two findings for one record")
	}
	if got := k.Describe(); got != "revoked" {
		t.Errorf("described as %q", got)
	}
}

// A testing key is one a verifier is told not to act on.
func TestATestingKeyIsSeen(t *testing.T) {
	p := publicKey(t, 2048)
	z := &zone{records: map[string][]string{
		"s1._domainkey.example.com": {"v=DKIM1; k=rsa; t=y; p=" + p},
		"s2._domainkey.example.com": {"v=DKIM1; k=rsa; t=s:y; p=" + p},
		"s3._domainkey.example.com": {"v=DKIM1; k=rsa; t=s; p=" + p},
	}}

	got := Check(context.Background(), z, "example.com", Named("s1,s2,s3"))
	if len(got.Keys) != 3 {
		t.Fatalf("got %+v", got.Keys)
	}
	if !got.Keys[0].Testing || !got.Keys[1].Testing {
		t.Errorf("t=y was not read: %+v", got.Keys[:2])
	}
	if got.Keys[2].Testing {
		t.Error("t=s was read as testing, and it means something else entirely")
	}
}

// A record that merely mentions DKIM is not a key.
func TestOnlyARecordThatAnnouncesItselfIsAKey(t *testing.T) {
	p := publicKey(t, 2048)
	z := &zone{records: map[string][]string{
		// A note somebody left at the name.
		"a._domainkey.example.com": {"this is where the dkim key goes"},

		// No v=, which RFC 6376 permits, but it carries a key.
		"b._domainkey.example.com": {"k=rsa; p=" + p},

		// Announces itself.
		"c._domainkey.example.com": {"v=DKIM1; p=" + p},
	}}

	got := Check(context.Background(), z, "example.com", Named("a,b,c"))
	if len(got.Keys) != 3 {
		t.Fatalf("got %+v", got.Keys)
	}
	if got.Keys[0].Found {
		t.Error("a note at the selector name was counted as a key")
	}
	if !got.Keys[1].Found {
		t.Error("a record with no v= and a key in it was not counted; RFC 6376 permits it")
	}
	if !got.Keys[2].Found {
		t.Error("a record announcing itself was not counted")
	}
}

// A lookup that failed is not a selector with no key (R4).
func TestAFailedLookupIsNotAnAbsentKey(t *testing.T) {
	z := &zone{
		records: map[string][]string{},
		fail: map[string]error{
			"s1._domainkey.example.com": errors.New("the resolver at 198.51.100.1:53 did not answer"),
		},
	}

	got := Check(context.Background(), z, "example.com", Named("s1"))
	if len(got.Keys) != 1 {
		t.Fatalf("got %+v", got.Keys)
	}
	k := got.Keys[0]
	if k.Found {
		t.Error("a failed lookup produced a key")
	}
	if k.Reason == "" {
		t.Error("a failed lookup is indistinguishable from a selector holding nothing")
	}
	if strings.Contains(k.Reason, "198.51.100.1") {
		t.Errorf("the reason repeats the resolver's address: %q", k.Reason)
	}
}

// Where a selector came from is kept, because it changes what an absence means.
//
// A name the operator gave and a name a provider documents are different
// claims. Nothing at one the operator named is worth saying; nothing at one of
// ten provider defaults is not.
func TestWhereASelectorCameFromIsKept(t *testing.T) {
	z := &zone{records: map[string][]string{}}

	selectors := append(Named("mine"), DocumentedSelectors()...)
	got := Check(context.Background(), z, "example.com", selectors)

	if !got.Looked {
		t.Fatal("the check reports that it did not look")
	}

	var named, documented int
	for _, k := range got.Keys {
		switch k.Source {
		case FromOperator:
			named++
		case FromProvider:
			documented++
		default:
			t.Errorf("%q came from nowhere", k.Selector)
		}
	}
	if named != 1 {
		t.Errorf("%d selectors came from the operator, want 1", named)
	}
	if documented == 0 {
		t.Error("no selector came from a provider's documentation")
	}
}

// Every documented selector names who documents it.
//
// The condition this list exists under. A set of likely names somebody here
// made up would be a threshold nobody can argue with; a set each provider
// publishes is a citation, and it is only a citation if the provider is named.
func TestEveryDocumentedSelectorNamesItsProvider(t *testing.T) {
	if len(Documented) == 0 {
		t.Fatal("the list is empty, so this test checks nothing")
	}

	seen := map[string]bool{}
	for _, d := range Documented {
		if d.Selector == "" || d.Provider == "" {
			t.Errorf("%+v is missing half of itself", d)
		}
		if seen[d.Selector] {
			t.Errorf("%q is listed twice", d.Selector)
		}
		seen[d.Selector] = true

		if ProviderOf(d.Selector) != d.Provider {
			t.Errorf("ProviderOf(%q) does not name %q", d.Selector, d.Provider)
		}
	}
}

// One selector is asked about once, however many times it is given.
func TestASelectorIsAskedAboutOnce(t *testing.T) {
	z := &zone{records: map[string][]string{}}

	Check(context.Background(), z, "example.com", Named("s1,s1,S1, s1 "))
	if len(z.asked) != 1 {
		t.Errorf("one selector was asked about %d times: %v", len(z.asked), z.asked)
	}
}

// A list long enough to be a load generator is bounded.
func TestTheSelectorListIsBounded(t *testing.T) {
	z := &zone{records: map[string][]string{}}

	var many []Selector
	for i := range 100 {
		many = append(many, Selector{Name: "s" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Source: FromOperator})
	}

	Check(context.Background(), z, "example.com", many)
	if len(z.asked) > maxSelectors {
		t.Errorf("%d lookups were made and the bound is %d", len(z.asked), maxSelectors)
	}
}

// The name asked about is the one DKIM puts a key at.
func TestTheNameAskedAboutIsWhereAKeyLives(t *testing.T) {
	z := &zone{records: map[string][]string{}}

	Check(context.Background(), z, "example.com", Named("s1"))
	if len(z.asked) != 1 || z.asked[0] != "s1._domainkey.example.com" {
		t.Errorf("asked about %v", z.asked)
	}
}

// A key that cannot be parsed is still a key that was found.
//
// The size is what could not be read, not the record. Reporting "no key" for a
// key whose encoding this program did not understand would be a claim about the
// domain made out of a limit of ours.
func TestAKeyThatCannotBeParsedIsStillFound(t *testing.T) {
	z := &zone{records: map[string][]string{
		"s1._domainkey.example.com": {"v=DKIM1; k=rsa; p=notbase64!!!"},
	}}

	got := Check(context.Background(), z, "example.com", Named("s1"))
	if len(got.Keys) != 1 {
		t.Fatalf("got %+v", got.Keys)
	}
	k := got.Keys[0]
	if !k.Found {
		t.Error("a key this program could not parse was reported as absent")
	}
	if k.Bits != 0 {
		t.Errorf("bits = %d for a key that could not be read", k.Bits)
	}
	if k.Weak() {
		t.Error("a key whose size could not be read was called weak")
	}
	if got := k.Describe(); got != "RSA" && got != "rsa" && got != "published" {
		t.Logf("described as %q", got)
	}
}

// An Ed25519 key has no size worth printing.
//
// They are all one length, so a number beside one invites a comparison against
// the RSA floor that means nothing.
func TestAnEd25519KeyIsNotGivenASize(t *testing.T) {
	z := &zone{records: map[string][]string{
		"s1._domainkey.example.com": {"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
	}}

	got := Check(context.Background(), z, "example.com", Named("s1"))
	if len(got.Keys) != 1 {
		t.Fatalf("got %+v", got.Keys)
	}
	k := got.Keys[0]
	if !k.Found {
		t.Fatal("the key was not found")
	}
	if k.Bits != 0 {
		t.Errorf("an Ed25519 key was given a size of %d", k.Bits)
	}
	if k.Weak() {
		t.Error("an Ed25519 key was called weak against a floor written for RSA")
	}
	if got := k.Describe(); got != "Ed25519" {
		t.Errorf("described as %q", got)
	}
}

// A value from somebody else's zone is bounded before it travels.
func TestAnEnormousTagIsBounded(t *testing.T) {
	z := &zone{records: map[string][]string{
		"s1._domainkey.example.com": {"v=DKIM1; k=" + strings.Repeat("x", 5000)},
	}}

	got := Check(context.Background(), z, "example.com", Named("s1"))
	if len(got.Keys) != 1 {
		t.Fatalf("got %+v", got.Keys)
	}
	if len(got.Keys[0].Algorithm) > maxTagLength {
		t.Errorf("a %d-byte tag reached the report", len(got.Keys[0].Algorithm))
	}
}

// A selector that held nothing is not described.
//
// Two fields disagreeing about one record: the JSON said found:false beside
// describes:"published", because Describe fell through to a default that
// assumed a key was there. A reader of the raw output — or a page rendering the
// description without checking Found first — is told a key exists.
func TestASelectorThatHeldNothingIsNotDescribed(t *testing.T) {
	z := &zone{records: map[string][]string{}}

	got := Check(context.Background(), z, "example.com", Named("absent"))
	if len(got.Keys) != 1 {
		t.Fatalf("got %+v", got.Keys)
	}
	if got.Keys[0].Found {
		t.Fatal("a key was found where none was published")
	}
	if d := got.Keys[0].Describe(); d != "" {
		t.Errorf("a selector holding nothing is described as %q", d)
	}

	// And one that could not be read is not described either: that is a
	// failure to look, not a key.
	broken := &zone{fail: map[string]error{
		"s1._domainkey.example.com": errors.New("no answer"),
	}}
	unread := Check(context.Background(), broken, "example.com", Named("s1"))
	if d := unread.Keys[0].Describe(); d != "" {
		t.Errorf("a selector that could not be read is described as %q", d)
	}
}
