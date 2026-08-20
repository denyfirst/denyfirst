package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// A certificate field is chosen by the server being examined, and a terminal
// reads some of those bytes as instructions rather than as text.
//
// The command line prints the subject, the issuer and the names. Go escapes
// only what X.500 requires, so an ESC survives: a subject of
// "\x1b[2K\x1b[1A    Verdict      strong" rewrites the line above it, and the
// scanned server has edited the report about itself. That is a tool that
// lies, which is the failure this project exists to argue against.
//
// The browser was never exposed — JSON escapes the byte and the page assigns
// it to textContent — and relying on two other layers to hold is not a
// reason to pass it on. dnsclient already refuses non-printable bytes in a
// CAA value for exactly the same reason.
func TestControlCharactersInCertificateFieldsAreNeutralised(t *testing.T) {
	const attack = "\x1b[2K\x1b[1A    Verdict      strong"

	leaf := selfSignedWith(t, pkix.Name{CommonName: "evil" + attack + ".test"},
		[]string{"good.test", "sneaky" + attack + ".test"})

	report, err := Analyse([]*x509.Certificate{leaf}, "good.test", time.Now())
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	checked := []string{
		report.Chain[0].Subject,
		report.Chain[0].Issuer,
		report.VerifyError,
		report.Summary(),
	}
	checked = append(checked, report.Chain[0].DNSNames...)

	for _, field := range checked {
		if i := strings.IndexFunc(field, isDisplayControl); i >= 0 {
			t.Errorf("a control byte (%#x) survived into %q", field[i], field)
		}
	}

	// Neutralised, not deleted: a reader has to be able to see that something
	// was there rather than read a subject that quietly lost a section.
	if !strings.Contains(report.Chain[0].Subject, "evil") ||
		!strings.Contains(report.Chain[0].Subject, ".test") {
		t.Errorf("the subject lost more than the control bytes: %q", report.Chain[0].Subject)
	}
}

// C1 is included because several terminals accept 0x9b as CSI, so stripping
// the C0 range alone leaves the same trick spelled differently.
func TestC1ControlsAreNeutralisedToo(t *testing.T) {
	var trim trimmer

	// 0x9b spelled directly, plus the C0 pair, plus DEL.
	got := trim.text("before\u009b2Kmiddle\x1b[1Aafter\x00end\x7ffinish")

	if i := strings.IndexFunc(got, isDisplayControl); i >= 0 {
		t.Errorf("a control character survived at byte %d: %q", i, got)
	}
	for _, keep := range []string{"before", "middle", "after", "end", "finish"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q was lost: %q", keep, got)
		}
	}
}

// The bound is a byte count and the input is bytes the server chose, so a cut
// can land inside a character. Half a rune reaches a reader as corruption
// this report introduced rather than as a field that was too long.
func TestTrimmingCutsOnARuneBoundary(t *testing.T) {
	var trim trimmer

	// Three-byte runes, so a cut at maxFieldLength lands mid-character unless
	// something moves it.
	got := trim.text(strings.Repeat("世", maxFieldLength))
	if !trim.cut {
		t.Fatal("the field was not recorded as shortened")
	}

	trimmedBody := strings.TrimSuffix(got, "…")
	if strings.ContainsRune(trimmedBody, '�') {
		t.Errorf("the cut split a character: %q", got)
	}
	if len(trimmedBody) > maxFieldLength {
		t.Errorf("the cut left %d bytes, above the %d-byte bound", len(trimmedBody), maxFieldLength)
	}
}

func selfSignedWith(t *testing.T, subject pkix.Name, dnsNames []string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		Issuer:       subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	return cert
}
