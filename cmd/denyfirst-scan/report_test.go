package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/dnsclient"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/scan"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// Fixed, so certificate arithmetic in the report is the same on every run.
var reportNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

type serverOpts struct {
	minVersion uint16
	maxVersion uint16
	suites     []uint16
	names      []string
	notBefore  time.Time
	notAfter   time.Time
}

// testServer starts a TLS server on the loopback and returns its port.
func testServer(t *testing.T, o serverOpts) string {
	t.Helper()

	if o.notBefore.IsZero() {
		o.notBefore = reportNow.Add(-30 * 24 * time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = reportNow.Add(60 * 24 * time.Hour)
	}
	if len(o.names) == 0 {
		o.names = []string{"example.test"}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x5eed),
		Subject:      pkix.Name{CommonName: o.names[0]},
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		DNSNames:     o.names,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   o.minVersion,
		MaxVersion:   o.maxVersion,
		CipherSuites: o.suites,
	})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck // a test server
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
			}(c)
		}
	}()

	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("reading the listener address: %v", err)
	}
	return port
}

// toLoopback sends every connection to one port, whatever name was asked for,
// so a scan can carry a real hostname without a real address behind it.
func toLoopback(port string) tlsprobe.DialFunc {
	var d net.Dialer
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}
}

// noResolver stands for a machine that cannot look anything up. The report has
// to say the check did not happen, which is not the same as saying nothing was
// found, and that distinction is the one R12 is about.
func noResolver() *dnsclient.Client {
	return &dnsclient.Client{
		Timeout: 200 * time.Millisecond,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no resolver is configured on this machine")
		},
	}
}

// report runs a scan and renders it exactly as the command does.
func report(t *testing.T, port string, resolver *dnsclient.Client) string {
	t.Helper()

	scanner := &scan.Scanner{
		Prober: &tlsprobe.Prober{
			Dial:             toLoopback(port),
			HandshakeTimeout: 3 * time.Second,
			TotalTimeout:     30 * time.Second,
		},
		AllowAnyPort: true,
		Resolver:     resolver,
		Now:          func() time.Time { return reportNow },
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := scanner.Scan(ctx, "example.test:"+port)
	if err != nil {
		t.Fatalf("scanning: %v", err)
	}

	var out strings.Builder
	printReport(&out, result{Result: res})
	return out.String()
}

// scanned is report's sibling: the same scan, handed back rather than
// printed, for a test whose subject is the notes and not the prose.
func scanned(t *testing.T, port string, resolver *dnsclient.Client) *scan.Result {
	t.Helper()

	scanner := &scan.Scanner{
		Prober: &tlsprobe.Prober{
			Dial:             toLoopback(port),
			HandshakeTimeout: 3 * time.Second,
			TotalTimeout:     30 * time.Second,
		},
		AllowAnyPort: true,
		Resolver:     resolver,
		Now:          func() time.Time { return reportNow },
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := scanner.Scan(ctx, "example.test:"+port)
	if err != nil {
		t.Fatalf("scanning: %v", err)
	}
	return res
}

// The report a person reads is built here and read here.
//
// Three sentences were wrong at once on 2026-08-22 — a version that was never
// measured drawn as refused, a CAA value printed as one string, and a
// revocation line that did not match the state behind it. Every one was found
// by a person looking at a live report, because the tests in this repository
// check data structures and the source text of the renderers, and nothing
// built a report and read it.
func TestAReportSaysWhatWasMeasured(t *testing.T) {
	port := testServer(t, serverOpts{minVersion: tls.VersionTLS12, maxVersion: tls.VersionTLS13})
	page := report(t, port, noResolver())
	t.Logf("\n%s", page)

	for _, want := range []struct{ text, why string }{
		{"example.test", "the report has to name what was scanned"},
		{"Verdict", "the verdict is the first thing a reader looks for"},
		{"Protocol versions", "the version table"},
		{"TLS 1.3", "a version this server speaks"},
		{"TLS 1.0", "a version this server refuses, which still has to appear"},
		{"Key exchange", "the one measurement that costs the scanned server an extra handshake"},
		{"Certificate", "the certificate section"},
		{"Fingerprint", "how a reader identifies the certificate they are looking at"},
	} {
		if !strings.Contains(page, want.text) {
			t.Errorf("the report does not contain %q — %s", want.text, want.why)
		}
	}
}

// A server that answers TCP and says nothing. Every version fails to be
// measured, and none of them refused anything.
func silentServer(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("reading the listener address: %v", err)
	}
	return port
}

// R12 on the face of the report: a version nobody could measure is not drawn
// as one the server refused.
//
// The page said "refused" for every version it failed to reach, which reads in
// the server's favour — "TLS 1.0 refused" is what a correct configuration
// looks like, and it was being printed for a handshake that never happened.
func TestAVersionThatCouldNotBeMeasuredIsNotDrawnAsRefused(t *testing.T) {
	page := report(t, silentServer(t), noResolver())
	t.Logf("\n%s", page)

	if !strings.Contains(page, "not measured") {
		t.Error("nothing could be measured and the report does not say so anywhere")
	}
	if strings.Contains(page, "refused") {
		t.Error("the report says a version was refused; this server refused nothing, it answered nothing")
	}
	if !strings.Contains(page, "ungraded") {
		t.Errorf("nothing was measured and the verdict is not ungraded:\n%s", page)
	}
}

// The two faces of one report show the same facts.
//
// They are rendered by different code in different languages — this file for a
// terminal, app.js for a browser — from one result. Nothing compared them, and
// on 2026-08-31 the terminal was missing the Issuance line entirely: the answer
// to "who may issue a certificate for this name" reached a reader with a
// browser and nobody at a command line, and not in the notes either.
//
// Matched on the labels rather than on the sentences, because the sentences
// are allowed to differ in wrapping and in punctuation. What may not differ is
// which questions the report answers.
func TestBothFacesOfTheReportShowTheSameFacts(t *testing.T) {
	// The terminal spells two of these differently. A different word for one
	// fact is not a missing fact.
	spelling := map[string]string{
		"SHA-256": "Fingerprint",
	}

	// Differences that are real and are being carried deliberately, each with
	// what it would take to close it. Anything not listed here has to be on
	// both faces.
	deliberate := map[string]string{}

	script, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page's renderer: %v", err)
	}
	source := string(script)

	start := strings.Index(source, "function certificate(")
	if start < 0 {
		t.Fatal("app.js has no certificate section, so this test compares nothing")
	}
	end := strings.Index(source[start:], "\n}\n")
	if end < 0 {
		t.Fatal("could not find the end of the certificate section")
	}
	section := source[start : start+end]

	labels := regexp.MustCompile(`pair\("([^"]+)"`).FindAllStringSubmatch(section, -1)
	if len(labels) < 5 {
		t.Fatalf("found only %d labels in the certificate section, which is too few to be right", len(labels))
	}

	port := testServer(t, serverOpts{minVersion: tls.VersionTLS12, maxVersion: tls.VersionTLS13})
	page := report(t, port, noResolver())

	// A labelled field, not the word anywhere. "Revocation was not checked"
	// appears in the notes of a report that has no Revocation line, and
	// reading that as the line is how this test would have passed while the
	// fact was missing.
	shown := func(label string) bool {
		return regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(label) + `\s+\S`).MatchString(page)
	}

	for _, m := range labels {
		label := m[1]
		if reason, known := deliberate[label]; known {
			if shown(label) {
				t.Errorf("%q is listed as a deliberate difference and the terminal now shows it. "+
					"Remove it from the list: a carried difference that has been closed reads as "+
					"though it is still open.\n  listed reason: %s", label, reason)
			}
			continue
		}
		want := label
		if alt, ok := spelling[label]; ok {
			want = alt
		}
		if !shown(want) {
			t.Errorf("the page shows %q and the terminal report does not. Either print it here, or "+
				"add it to the deliberate list with what it would take to close it. A fact on one "+
				"face and not the other is a report that says different things to different readers.",
				label)
		}
	}
}

// Invariant R16, extended to the headings.
//
// The report has two faces and they are written in two languages. Until now
// the rule was that they show the same facts; the notes add a second thing
// they have to agree on, which is how those facts are grouped. A reader
// holding the terminal output beside the page should not have to work out that
// "Observed" here is the same section as "Observed" there, and a section that
// existed on one face and not the other would be a fact shown to one reader
// and hidden from the other.
//
// Read out of both sources rather than restated here, so that renaming a
// section in one place and not the other fails instead of drifting.
func TestBothFacesNameTheSameNoteSections(t *testing.T) {
	script, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}

	// The page: kind and title out of the NOTE_SECTIONS table, in order.
	pairs := regexp.MustCompile(`kind:\s*"([a-z-]+)",\s*\n\s*title:\s*"([^"]+)"`).
		FindAllStringSubmatch(string(script), -1)
	if len(pairs) == 0 {
		t.Fatal("the script declares no note sections; the page cannot be showing them")
	}

	if len(pairs) != len(noteSections) {
		t.Fatalf("the page has %d note sections and the terminal has %d",
			len(pairs), len(noteSections))
	}
	for i, got := range pairs {
		want := noteSections[i]
		if got[1] != string(want.kind) {
			t.Errorf("section %d: the page groups %q, the terminal groups %q",
				i, got[1], want.kind)
		}
		if got[2] != want.heading {
			t.Errorf("section %d: the page calls it %q, the terminal calls it %q",
				i, got[2], want.heading)
		}
	}
}

// A note reaches a report only with a kind on it.
//
// The kind decides the heading, and a note with none is filed under whichever
// heading renders first — which a reader cannot tell apart from a deliberate
// classification, and which is wrong. This runs a whole scan rather than
// checking one producer, so a note added anywhere in the pipeline is covered
// without anybody remembering to come back here.
func TestEveryNoteInAReportCarriesAKind(t *testing.T) {
	port := testServer(t, serverOpts{})
	notes := scanned(t, port, noResolver()).Notes()

	if len(notes) == 0 {
		t.Fatal("a full scan produced no notes at all, so this proves nothing")
	}

	sectioned := map[policy.NoteKind]bool{}
	for _, section := range noteSections {
		sectioned[section.kind] = true
	}

	for _, note := range notes {
		switch {
		case sectioned[note.Kind]:
			// Rendered under its heading, on both faces.

		case note.Kind == policy.KindStanding:
			// Not rendered, pointed at — so it has to be one of the limits
			// the page and -limits enumerate. A standing sentence written
			// inline would leave the report saying four limits exist while
			// carrying a fifth nothing explains.
			if !policy.IsStandingLimit(note.Text) {
				t.Errorf("a standing note is not in policy.StandingLimits(), so nothing explains it:\n  %s",
					note.Text)
			}

		default:
			t.Errorf("a note carries the kind %q, which is neither rendered nor pointed at:\n  %s",
				note.Kind, note.Text)
		}
	}
}

// The report says how many limits it did not print, and where they are.
func TestTheReportPointsAtTheLimitsItDoesNotPrint(t *testing.T) {
	port := testServer(t, serverOpts{})
	text := report(t, port, noResolver())
	standing := policy.NotesOfKind(scanned(t, port, noResolver()).Notes(), policy.KindStanding)

	if len(standing) == 0 {
		t.Fatal("this scan produced no standing limits, so this proves nothing")
	}
	for _, want := range []string{
		"Limits of this method",
		fmt.Sprintf("%d apply to every scan", len(standing)),
		"denyfirst-scan -limits",
		methodPage,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not carry %q:\n%s", want, text)
		}
	}

	// And none of their text is printed, or moving them changed nothing.
	for _, limit := range policy.StandingLimits() {
		if strings.Contains(text, limit.Text) {
			t.Errorf("the report still prints the standing limit %q in full", limit.Title)
		}
	}
}

// What holds reaches both faces, and says the same things on each.
//
// Invariant R16. The affirmative summary is the newest thing a reader meets
// and the easiest to add to one renderer and forget in the other, which would
// leave two readers of one scan with different impressions of the same server.
func TestWhatHoldsIsOnBothFacesOfTheReport(t *testing.T) {
	port := testServer(t, serverOpts{})
	res := scanned(t, port, noResolver())
	text := report(t, port, noResolver())

	if len(res.Assurances) == 0 {
		t.Fatal("a completed scan established nothing worth stating, so this proves nothing")
	}

	if !strings.Contains(text, "  What holds\n") {
		t.Errorf("the terminal report has no What holds block:\n%s", text)
	}
	// Compared with whitespace collapsed. The terminal wraps at seventy
	// columns and indents the continuation, so a sentence longer than that
	// arrives with newlines and spaces inside it — which is the wrapping
	// working, not the sentence missing. Two of the assurances are long
	// enough for it and this test failed on exactly those two before it was
	// told.
	flat := collapse(text)
	for _, a := range res.Assurances {
		if !strings.Contains(flat, collapse(a.Text)) {
			t.Errorf("the terminal report does not carry the assurance %q:\n  %s", a.ID, a.Text)
		}
	}

	script, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	for _, required := range []string{
		"function assurances(list)",
		"data.assurances",
		`"What holds"`,
		"item.text",
	} {
		if !strings.Contains(string(script), required) {
			t.Errorf("the page does not render what holds: missing %q", required)
		}
	}
}

// An assurance is never produced by a rule failing to fire.
//
// The whole risk of an affirmative summary is that it gets read off the
// findings rather than off the measurements, at which point "no rule fired"
// becomes a reassurance — and no rule fires on a scan that reached nothing.
// This runs a scan against a port with no server on it.
func TestAScanThatReachedNothingHoldsNothing(t *testing.T) {
	// A listener that accepts and never speaks TLS, so every handshake fails
	// and nothing about the connection is established.
	port := silentServer(t)
	res := scanned(t, port, noResolver())

	for _, a := range res.Assurances {
		if a.ID != "no-obsolete" {
			t.Errorf("a scan that negotiated nothing claims %q holds:\n  %s", a.ID, a.Text)
		}
	}
}

// collapse turns every run of whitespace into one space, so a comparison is
// about the words rather than about where the renderer broke the line.
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }
