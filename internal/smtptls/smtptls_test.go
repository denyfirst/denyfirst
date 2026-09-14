package smtptls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/safedial"
)

const exchanger = "mx.example.test"

// script is an SMTP server that says what it is told to and records what it
// hears.
type script struct {
	greeting      string
	ehlo          string
	starttls      string
	afterStarttls string
	cert          *tls.Certificate

	mu    sync.Mutex
	heard []string
}

func (s *script) record(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heard = append(s.heard, line)
}

func (s *script) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.heard...)
}

func (s *script) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := io.WriteString(conn, s.greeting); err != nil {
		return
	}

	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.TrimRight(line, "\r\n")
		s.record(command)

		verb := strings.ToUpper(strings.SplitN(command, " ", 2)[0])
		switch verb {
		case "EHLO", "HELO":
			_, _ = io.WriteString(conn, s.ehlo)
		case "STARTTLS":
			_, _ = io.WriteString(conn, s.starttls+s.afterStarttls)
			if s.cert == nil || !strings.HasPrefix(s.starttls, "220") {
				continue
			}
			server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*s.cert}})
			if err := server.Handshake(); err != nil {
				return
			}
			if after, err := bufio.NewReader(server).ReadString('\n'); err == nil {
				s.record(strings.TrimRight(after, "\r\n"))
			}
			return
		case "QUIT":
			_, _ = io.WriteString(conn, "221 bye\r\n")
			return
		default:
			_, _ = io.WriteString(conn, "502 not implemented\r\n")
		}
	}
}

// offering is a well-behaved exchanger that offers STARTTLS.
func offering(cert *tls.Certificate) *script {
	return &script{
		greeting: "220 mx.example.test ESMTP\r\n",
		ehlo:     "250-mx.example.test greets you\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 8BITMIME\r\n",
		starttls: "220 go ahead\r\n",
		cert:     cert,
	}
}

func pipeProber(s *script, roots *x509.CertPool) *Prober {
	return &Prober{
		HeloName: "client.example.test",
		Roots:    roots,
		Timeout:  3 * time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go s.serve(server)
			return client, nil
		},
	}
}

// certificateFor mints a self-signed certificate naming one host, and a pool
// that trusts it.
func certificateFor(t *testing.T, name string) (*tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(25),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{name},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func probe(t *testing.T, p *Prober) Result {
	t.Helper()
	done := make(chan Result, 1)
	go func() { done <- p.Probe(context.Background(), exchanger) }()
	select {
	case got := <-done:
		return got
	case <-time.After(10 * time.Second):
		t.Fatal("Probe did not return; a conversation with one exchanger is bounded")
		return Result{}
	}
}

// An exchanger offering STARTTLS is upgraded, and its certificate judged.
func TestAnExchangerOfferingSTARTTLSIsUpgradedAndJudged(t *testing.T) {
	cert, roots := certificateFor(t, exchanger)
	s := offering(cert)

	got := probe(t, pipeProber(s, roots))
	if !got.Connected || !got.Measured || !got.Offered || !got.Upgraded {
		t.Fatalf("got %+v; the exchanger offered STARTTLS and negotiated", got)
	}
	if !got.Trusted || !got.NameMatches || got.CertificateReason != "" {
		t.Errorf("a certificate trusted by the store and naming the exchanger was judged %+v", got)
	}
	if got.Version == "" || got.Suite == "" {
		t.Errorf("version %q, suite %q; what was negotiated is not said", got.Version, got.Suite)
	}

	// And the chain it presented travels, for the DANE check to read.
	if len(got.Chain) != 1 || !bytes.Equal(got.Chain[0].Raw, cert.Certificate[0]) {
		t.Errorf("the result carries %d certificates; the exchanger presented its own, and a DANE record is checked against it", len(got.Chain))
	}

	// And the goodbye went over the encrypted connection.
	commands := s.commands()
	if last := commands[len(commands)-1]; last != "QUIT" {
		t.Errorf("the last thing heard was %q, want QUIT over TLS; heard %v", last, commands)
	}
}

// Nothing is ever sent that names a sender, a recipient or a message.
//
// The claim the whole package rests on. A conversation that sent MAIL FROM
// would be the start of delivering something, and a RCPT TO would be asking an
// exchanger about a person — the one kind of question this tool does not ask.
func TestNoSenderRecipientOrMessageIsEverNamed(t *testing.T) {
	cert, roots := certificateFor(t, exchanger)

	for name, s := range map[string]*script{
		"offering":     offering(cert),
		"not offering": {greeting: "220 hi\r\n", ehlo: "250-mx greets you\r\n250 8BITMIME\r\n"},
		"refusing":     {greeting: "554 go away\r\n"},
	} {
		probe(t, pipeProber(s, roots))

		for _, command := range s.commands() {
			verb := strings.ToUpper(strings.SplitN(command, " ", 2)[0])
			switch verb {
			case "EHLO", "STARTTLS", "QUIT":
			default:
				t.Errorf("%s: the exchanger heard %q; only EHLO, STARTTLS and QUIT are ever sent", name, command)
			}
		}
	}
}

// An exchanger offering no STARTTLS is measured as offering none.
func TestAnExchangerWithoutSTARTTLSIsMeasuredAsNotOffering(t *testing.T) {
	s := &script{
		greeting: "220 mx.example.test ESMTP\r\n",
		ehlo:     "250-mx.example.test greets you\r\n250-PIPELINING\r\n250 8BITMIME\r\n",
	}
	got := probe(t, pipeProber(s, nil))
	if !got.Measured || got.Offered || got.Upgraded {
		t.Errorf("got %+v; the exchanger said what it offers and STARTTLS was not among it", got)
	}
}

// The server's own name in the first line is not a keyword.
func TestAGreetingNamedSTARTTLSIsNotAnOffer(t *testing.T) {
	s := &script{
		greeting: "220 starttls ESMTP\r\n",
		ehlo:     "250-STARTTLS greets you\r\n250 8BITMIME\r\n",
	}
	if got := probe(t, pipeProber(s, nil)); got.Offered {
		t.Error("the greeting line was read as an offer of STARTTLS")
	}
}

// A certificate for another name does not match, and a certificate nobody
// trusts does not verify — two questions, asked separately.
func TestTheCertificateIsJudgedOnTrustAndNameSeparately(t *testing.T) {
	other, otherRoots := certificateFor(t, "mail.elsewhere.test")
	got := probe(t, pipeProber(offering(other), otherRoots))
	if !got.Upgraded || !got.Trusted || got.NameMatches {
		t.Errorf("a trusted certificate for another name was judged %+v", got)
	}
	if got.CertificateReason == "" {
		t.Error("nothing says why the certificate does not do")
	}

	cert, _ := certificateFor(t, exchanger)
	_, strangerRoots := certificateFor(t, "a.stranger.test")
	got = probe(t, pipeProber(offering(cert), strangerRoots))
	if !got.Upgraded || got.Trusted || !got.NameMatches {
		t.Errorf("a certificate naming the exchanger that nothing trusts was judged %+v", got)
	}
	if !strings.Contains(got.CertificateReason, "chain") {
		t.Errorf("reason = %q; want it to say the chain reaches nothing trusted", got.CertificateReason)
	}
}

// A refusal instead of a greeting is not a measurement, and nothing more is
// said to a server that has refused.
//
// The script answers EHLO as though it were fine. Until 2026-09-13 it answered
// nothing, so a client that ignored the refusal and pressed on timed out and
// was reported unmeasured anyway — and a sabotage removing the check escaped.
func TestARefusedGreetingIsNotMeasured(t *testing.T) {
	s := &script{greeting: "554 no service here\r\n", ehlo: "250-mx greets you\r\n250 STARTTLS\r\n"}
	got := probe(t, pipeProber(s, nil))
	if got.Measured || got.Offered || got.Reason == "" {
		t.Errorf("got %+v; a server that refused before anything was asked has not said what it offers", got)
	}
	for _, command := range s.commands() {
		if strings.HasPrefix(strings.ToUpper(command), "EHLO") {
			t.Errorf("EHLO was sent to a server that had refused the connection: heard %v", s.commands())
		}
	}
}

// A refused EHLO is not an exchanger offering nothing.
func TestARefusedEHLOIsNotMeasured(t *testing.T) {
	got := probe(t, pipeProber(&script{greeting: "220 hi\r\n", ehlo: "550 your name is not welcome\r\n"}, nil))
	if got.Measured || got.Reason == "" {
		t.Errorf("got %+v; an EHLO the server refused is not a list of what it offers", got)
	}
}

// Anything sent before encryption begins stops the conversation.
//
// RFC 3207 forbids it, and it is the shape of a command injected on the path. A
// client that negotiated TLS anyway would read those bytes as though they had
// arrived encrypted.
func TestDataBeforeEncryptionStopsTheConversation(t *testing.T) {
	cert, roots := certificateFor(t, exchanger)
	s := offering(cert)
	s.afterStarttls = "250 injected\r\n"

	got := probe(t, pipeProber(s, roots))
	if got.Upgraded {
		t.Error("TLS was negotiated over a conversation carrying bytes sent before it began")
	}
	if !strings.Contains(got.Reason, "RFC 3207") {
		t.Errorf("reason = %q", got.Reason)
	}
}

// A line longer than RFC 5321 allows is not read to its end.
func TestAnEnormousLineIsNotReadToItsEnd(t *testing.T) {
	got := probe(t, pipeProber(&script{greeting: "220 " + strings.Repeat("A", 20000) + "\r\n"}, nil))
	if got.Connected {
		t.Errorf("a 20000-byte greeting was accepted: %+v", got)
	}
}

// A reply longer than the bound is refused, even when it does end.
//
// This sent five hundred lines and never a last one until 2026-09-13, so a
// client with no bound at all ran into the connection deadline and reported the
// same thing — and a sabotage removing the bound escaped. This reply ends
// properly, with STARTTLS on its final line, after more lines than a reply may
// have: only the bound refuses it.
func TestAReplyThatNeverEndsIsBounded(t *testing.T) {
	got := probe(t, pipeProber(&script{
		greeting: "220 hi\r\n",
		ehlo:     "250-mx greets you\r\n" + strings.Repeat("250-EXTENSION\r\n", maxLines+10) + "250 STARTTLS\r\n",
	}, nil))
	if got.Measured || got.Offered {
		t.Errorf("a reply of %d lines was read as a list of extensions: %+v", maxLines+12, got)
	}
}

// The configured name cannot become a second command.
//
// It is written into a line built by hand. A carriage return in it would end
// EHLO and start whatever follows — the one way an operator's typo, or a
// value from somewhere nobody checked, could make this send MAIL FROM.
func TestTheEHLONameCannotCarryACommand(t *testing.T) {
	restore := osHostname
	osHostname = func() (string, error) { return "box.example.test", nil }
	t.Cleanup(func() { osHostname = restore })

	s := &script{greeting: "220 hi\r\n", ehlo: "250 mx\r\n"}
	p := pipeProber(s, nil)
	p.HeloName = "evil.example.test\r\nMAIL FROM:<someone@example.test>"
	probe(t, p)

	commands := s.commands()
	if len(commands) == 0 || commands[0] != "EHLO box.example.test" {
		t.Errorf("heard %v; want the hostile name refused and the machine's own name sent", commands)
	}
	for _, c := range commands {
		if strings.Contains(strings.ToUpper(c), "MAIL") {
			t.Errorf("the exchanger heard %q", c)
		}
	}
}

// The name follows RFC 5321: configured, then a qualified host name, then an
// address literal.
func TestTheEHLONameIsTheClientsOwn(t *testing.T) {
	restore := osHostname
	t.Cleanup(func() { osHostname = restore })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		if c, err := listener.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	defer conn.Close()

	osHostname = func() (string, error) { return "box.example.test", nil }
	if got := (&Prober{HeloName: "mail.example.test"}).heloName(conn); got != "mail.example.test" {
		t.Errorf("a configured name gave %q", got)
	}
	if got := (&Prober{}).heloName(conn); got != "box.example.test" {
		t.Errorf("a qualified host name gave %q", got)
	}

	osHostname = func() (string, error) { return "DESKTOP-AB12", nil }
	if got := (&Prober{}).heloName(conn); got != "[127.0.0.1]" {
		t.Errorf("an unqualified host name gave %q, want the address literal", got)
	}

	for addr, want := range map[net.Addr]string{
		&net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 5000}:        "[203.0.113.5]",
		&net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.5"), Port: 5000}: "[203.0.113.5]",
		&net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 5000}:        "[IPv6:2001:db8::1]",
	} {
		if got := addressLiteral(addr); got != want {
			t.Errorf("addressLiteral(%s) = %q, want %q", addr, got, want)
		}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "dial tcp 203.0.113.9:25: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// A connection that never opens says port 25 may be blocked here, and is not
// blamed on the exchanger (R3d).
func TestAConnectTimeoutSaysPort25MayBeBlocked(t *testing.T) {
	p := &Prober{Dial: func(context.Context, string, string) (net.Conn, error) { return nil, timeoutError{} }}

	got := probe(t, p)
	if !got.ConnectTimedOut {
		t.Error("a connection that timed out is not marked as one")
	}
	if !strings.Contains(got.Reason, "port 25") || !strings.Contains(got.Reason, "network") {
		t.Errorf("reason = %q; want it to say the network may be blocking port 25", got.Reason)
	}
	if got.Connected || got.Measured {
		t.Errorf("got %+v", got)
	}
}

// No reason carries an address or Go's wording (I6).
func TestNoReasonNamesTheMachine(t *testing.T) {
	for _, err := range []error{
		timeoutError{},
		errors.New("dial tcp 203.0.113.9:25: connect: connection refused"),
		errors.New("lookup mx.example.test on 185.12.64.2:53: no such host"),
		errors.New("something nobody has seen before at 10.0.0.2"),
	} {
		reason, _ := dialReason(err)
		for _, leak := range []string{"203.0.113.9", "185.12.64.2", "10.0.0.2", "dial tcp", "lookup"} {
			if strings.Contains(reason, leak) {
				t.Errorf("dialReason(%q) = %q, carrying %q", err, reason, leak)
			}
		}
	}
}

// The default dialler reaches port 25 and nothing else, and no private address.
func TestTheDefaultDiallerReachesOnlyPort25OnPublicAddresses(t *testing.T) {
	dial := (&Prober{}).dialFunc()
	for _, address := range []string{"127.0.0.1:25", "10.0.0.1:25", "[::1]:25", "93.184.216.34:443", "93.184.216.34:587"} {
		conn, err := dial(context.Background(), "tcp", address)
		if conn != nil {
			_ = conn.Close()
		}
		if !errors.Is(err, safedial.ErrBlocked) {
			t.Errorf("dialling %s gave %v, want the policy refusal", address, err)
		}
	}
}

// A silent server is given until the deadline and no longer.
func TestASilentExchangerIsBounded(t *testing.T) {
	p := &Prober{
		Timeout: 200 * time.Millisecond,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() { _, _ = io.Copy(io.Discard, server) }()
			return client, nil
		},
	}
	start := time.Now()
	got := probe(t, p)
	if got.Connected {
		t.Errorf("a server that said nothing was read as connected: %+v", got)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Probe waited %s on a silent exchanger with a 200ms budget", elapsed)
	}
}
