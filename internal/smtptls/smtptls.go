// Package smtptls asks a domain's mail exchangers whether they accept an
// encrypted connection, and what certificate they present when they do.
//
// # What is said, and nothing more
//
// One SMTP conversation per exchanger, on port 25, in the order RFC 5321 and
// RFC 3207 give it: read the greeting, send EHLO, read what the server offers,
// send STARTTLS if it offers it, negotiate TLS, send QUIT. That is the whole of
// it.
//
// No sender, recipient or message is ever named. There is no MAIL FROM, no RCPT
// TO and no DATA, so nothing is delivered, nothing is queued and nothing at the
// other end changes. What an exchanger's log records is a client that said hello,
// asked for encryption, and left — which is what every sending server that finds
// nothing to deliver looks like.
//
// # The name it gives
//
// EHLO carries a name, and RFC 5321 says it is the client's own: its fully
// qualified host name, or where it has none, its address in brackets. That is
// what is sent. A name the operator configures comes first; then this machine's
// host name, if it is fully qualified; then its address as a literal. Nothing is
// invented to hide who is asking — on a deployment somebody runs to check their
// own mail there is nothing to hide, and a name that does not exist is one a
// correctly configured server may refuse, which would be reported as a server
// that could not be measured.
//
// # What is read
//
// Replies are bounded before they are believed: a line is at most the thousand
// bytes RFC 5321 allows, and a reply at most sixty-four lines. The certificate
// is taken from the handshake and judged against the deployment's own trust
// store, the same store that decides the word "trusted" for the other checks
// (R7).
package smtptls

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/safedial"
	"github.com/denyfirst/denyfirst/internal/truststore"
)

const (
	// Port is the one port an exchanger is asked on: where mail is delivered
	// to it. Submission ports belong to a domain's users rather than to the
	// senders delivering to it, and are not what MTA-STS or DANE protect.
	Port = "25"

	// maxLine is the longest line RFC 5321 §4.5.3.1.5 permits in a reply,
	// CRLF included.
	maxLine = 1000

	// maxLines bounds one multi-line reply. An EHLO reply is a dozen lines;
	// sixty-four is generous and still a bound the server does not choose.
	maxLines = 64

	defaultTimeout = 20 * time.Second
)

// Result is what one exchanger answered.
//
// Four states and never two, because each is a different sentence: not
// reached, reached and not measured, measured and offering no encryption, and
// encrypted — with a certificate that does or does not verify.
type Result struct {
	Host string

	// Connected is true once a greeting arrived.
	Connected bool

	// Measured is true once the server said what it offers. Without it,
	// Offered false is silence rather than an exchanger offering nothing (R4).
	Measured bool

	// Offered is whether STARTTLS was among what the server offers.
	Offered bool

	// Upgraded is whether a TLS connection was negotiated after STARTTLS.
	Upgraded bool

	// Version and Suite are what was negotiated.
	Version string
	Suite   string

	// Trusted is whether the chain verifies against the deployment's store,
	// and NameMatches whether the leaf names this exchanger.
	Trusted     bool
	NameMatches bool

	// CertificateReason says why the certificate did not verify, as a phrase
	// that follows "the certificate does not verify:".
	CertificateReason string

	// Reason says why something was not measured.
	Reason string

	// ConnectTimedOut is true when no connection to port 25 opened before the
	// time ran out — which is what a network blocking outbound port 25 looks
	// like, and is therefore not established as a fact about the exchanger
	// (R3d).
	ConnectTimedOut bool
}

// Prober asks exchangers. The zero value is usable.
type Prober struct {
	// Dial opens the connection. Nil selects safedial, allowed port 25 alone,
	// which refuses private, loopback and reserved destinations.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots is the trust store a certificate is judged against. Nil means the
	// system store, resolved explicitly rather than left to the platform.
	Roots *x509.CertPool

	// HeloName is the name sent with EHLO. Empty means this machine's own:
	// see heloName.
	HeloName string

	// Timeout bounds the conversation with one exchanger. Zero means twenty
	// seconds.
	Timeout time.Duration

	// Now supplies the time a certificate is judged at. Nil means time.Now.
	Now func() time.Time
}

var (
	errLineTooLong  = errors.New("smtptls: a reply line is longer than rfc 5321 allows")
	errReplyTooLong = errors.New("smtptls: a reply has more lines than this client reads")
	errMalformed    = errors.New("smtptls: a reply is not an smtp reply")
)

// osHostname is os.Hostname, replaceable by a test.
var osHostname = os.Hostname

// Probe holds one conversation with one exchanger.
//
// Never returns an error: an exchanger that could not be measured is a Result
// carrying the reason, because a caller that had to tell a failed conversation
// from an exchanger offering nothing by inspecting an error would eventually
// stop doing it (R4).
func (p *Prober) Probe(ctx context.Context, host string) Result {
	host = strings.TrimSuffix(host, ".")
	out := Result{Host: host}

	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()

	conn, err := p.dialFunc()(ctx, "tcp", net.JoinHostPort(host, Port))
	if err != nil {
		out.Reason, out.ConnectTimedOut = dialReason(err)
		return out
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	r := bufio.NewReaderSize(conn, maxLine)

	code, _, err := readReply(r)
	if err != nil {
		out.Reason = conversationReason(err, "the server sent no greeting that could be read")
		return out
	}
	out.Connected = true
	if code != 220 {
		out.Reason = "the server answered the connection with a refusal instead of a greeting, so nothing was asked"
		quit(conn)
		return out
	}

	if err := writeLine(conn, "EHLO "+p.heloName(conn)); err != nil {
		out.Reason = "the connection closed before the greeting could be answered"
		return out
	}
	code, lines, err := readReply(r)
	if err != nil {
		out.Reason = conversationReason(err, "the reply to EHLO could not be read")
		return out
	}
	if code != 250 {
		out.Reason = "the server refused the EHLO greeting, so what it offers was not established"
		quit(conn)
		return out
	}

	out.Measured = true
	out.Offered = offersSTARTTLS(lines)
	if !out.Offered {
		quit(conn)
		return out
	}

	if err := writeLine(conn, "STARTTLS"); err != nil {
		out.Reason = "the connection closed before STARTTLS could be asked for"
		return out
	}
	code, _, err = readReply(r)
	if err != nil || code != 220 {
		out.Reason = "the server offered STARTTLS and did not accept it when asked"
		quit(conn)
		return out
	}

	// Anything already waiting was sent before encryption began, and RFC 3207
	// forbids it: it is the shape of a command injected by something on the
	// path, and bytes read here would be read as though they arrived over the
	// encrypted connection. Nothing is negotiated over a conversation that
	// has already been tampered with or is already broken.
	if r.Buffered() > 0 {
		out.Reason = "the server sent more before the encrypted connection began, which RFC 3207 forbids, so nothing was negotiated over it"
		return out
	}

	// Both settings gosec objects to are the purpose of the measurement. The
	// certificate is described rather than trusted, and it is verified below
	// against the deployment's own store; an old version is accepted because
	// reporting that an exchanger still negotiates one requires speaking it.
	//
	// #nosec G402 -- deliberate: a mail exchanger is measured, not trusted
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		out.Reason = "STARTTLS was accepted and no encrypted connection could be negotiated with this client"
		return out
	}

	state := tlsConn.ConnectionState()
	out.Upgraded = true
	out.Version = versionName(state.Version)
	out.Suite = tls.CipherSuiteName(state.CipherSuite)
	out.Trusted, out.NameMatches, out.CertificateReason = p.judge(state.PeerCertificates, host)

	quit(tlsConn)
	return out
}

// judge verifies a chain against the deployment's store, and its name.
//
// Two questions, asked separately, because a certificate can fail either one
// alone and the sentence a reader acts on differs: a chain nobody trusts is a
// certificate to replace, a trusted certificate for another name is an
// exchanger pointed at the wrong certificate.
func (p *Prober) judge(chain []*x509.Certificate, host string) (trusted, nameMatches bool, reason string) {
	if len(chain) == 0 {
		return false, false, "the server presented no certificate"
	}

	roots, err := truststore.Resolve(p.Roots)
	if err != nil {
		return false, false, "no trust store was available to judge it against"
	}

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}

	_, verifyErr := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   p.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	trusted = verifyErr == nil
	nameMatches = chain[0].VerifyHostname(host) == nil

	switch {
	case !trusted:
		reason = certificateReason(verifyErr)
	case !nameMatches:
		reason = "it does not name this exchanger"
	}
	return trusted, nameMatches, reason
}

// certificateReason names why a chain did not verify, as a fixed phrase.
func certificateReason(err error) string {
	var invalid x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	switch {
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return "it is outside its validity period"
	case errors.As(err, &unknown):
		return "it does not chain to a root this deployment trusts"
	case errors.As(err, &invalid):
		return "it is not valid for this use"
	default:
		return "it did not verify"
	}
}

// heloName is the name sent with EHLO, chosen the way RFC 5321 §4.1.4 says.
//
// The operator's own, if they gave one; this machine's host name, if it is
// fully qualified; this connection's local address as a literal. The last two
// are what the RFC describes, and a configured name is how an operator whose
// machine has neither says what it is.
func (p *Prober) heloName(conn net.Conn) string {
	if name := validName(p.HeloName); name != "" {
		return name
	}
	if hostname, err := osHostname(); err == nil {
		if name := validName(hostname); strings.Contains(name, ".") {
			return name
		}
	}
	if literal := addressLiteral(conn.LocalAddr()); literal != "" {
		return literal
	}

	// Only a connection with no address of its own reaches here — a test's
	// in-memory pipe. A bare host name is better than nothing, and nothing
	// is better than inventing one.
	if hostname, err := osHostname(); err == nil {
		if name := validName(hostname); name != "" {
			return name
		}
	}
	return "localhost"
}

// validName returns a name that may be written into an SMTP command, or empty.
//
// The operator's configured name reaches a command line built by hand, so a
// carriage return in it would be a second command. Only what a host name can
// hold is accepted.
func validName(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" || len(name) > 253 || strings.HasPrefix(name, "-") || strings.HasPrefix(name, ".") {
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

// addressLiteral writes an address the way RFC 5321 §4.1.3 does: [192.0.2.1],
// or [IPv6:2001:db8::1].
func addressLiteral(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		return "[" + ip.String() + "]"
	}
	return "[IPv6:" + ip.String() + "]"
}

// readReply reads one SMTP reply: its code, and the text of each line.
func readReply(r *bufio.Reader) (int, []string, error) {
	var (
		code  int
		lines []string
	)
	for range maxLines {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return 0, nil, errLineTooLong
		}
		if err != nil {
			return 0, nil, err
		}

		text := strings.TrimRight(string(line), "\r\n")
		if len(text) < 3 {
			return 0, nil, errMalformed
		}
		c, err := strconv.Atoi(text[:3])
		if err != nil || c < 200 || c > 599 || (code != 0 && c != code) {
			return 0, nil, errMalformed
		}
		code = c

		if len(text) > 4 {
			lines = append(lines, text[4:])
		} else {
			lines = append(lines, "")
		}

		switch {
		case len(text) == 3 || text[3] == ' ':
			return code, lines, nil
		case text[3] != '-':
			return 0, nil, errMalformed
		}
	}
	return 0, nil, errReplyTooLong
}

// offersSTARTTLS reports whether an EHLO reply lists the extension.
//
// The first line is the server's greeting and is not a keyword, so a server
// whose name happens to be "starttls" does not count as offering it.
func offersSTARTTLS(lines []string) bool {
	for i, line := range lines {
		if i == 0 {
			continue
		}
		if fields := strings.Fields(line); len(fields) > 0 && strings.EqualFold(fields[0], "STARTTLS") {
			return true
		}
	}
	return false
}

func writeLine(w io.Writer, line string) error {
	_, err := io.WriteString(w, line+"\r\n")
	return err
}

// quit says goodbye and does not wait for an answer. Waiting would only cost
// time, and nothing the server says next changes the result.
func quit(w io.Writer) { _ = writeLine(w, "QUIT") }

// dialReason turns a failure to connect into a phrase safe to publish, and
// says whether it was the kind a blocked outbound port 25 produces.
func dialReason(err error) (string, bool) {
	var netErr net.Error
	msg := err.Error()
	switch {
	case errors.Is(err, safedial.ErrBlocked):
		return "not contacted: this is not a destination the service will connect to", false
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "no connection to port 25 opened before the time ran out. Many networks block outbound " +
			"port 25, so this may describe the network this scan ran from rather than the exchanger", true
	case strings.Contains(msg, "connection refused"):
		return "the connection to port 25 was refused. Some networks that block outbound port 25 answer " +
			"this way on the exchanger's behalf, so it is not established as the exchanger's refusal", false
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "no addresses"):
		return "the exchanger's name did not resolve", false
	default:
		return "the exchanger could not be reached on port 25", false
	}
}

// conversationReason turns a failure mid-conversation into a phrase.
func conversationReason(err error, fallback string) string {
	var netErr net.Error
	switch {
	case errors.Is(err, errLineTooLong), errors.Is(err, errReplyTooLong), errors.Is(err, errMalformed):
		return "the server's reply was not SMTP this client could read"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "the server stopped answering before the conversation finished"
	default:
		return fallback
	}
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "an unrecognised version"
	}
}

func (p *Prober) dialFunc() func(context.Context, string, string) (net.Conn, error) {
	if p.Dial != nil {
		return p.Dial
	}
	d := &safedial.Dialer{Timeout: p.timeout(), AllowedPorts: []string{Port}}
	return d.DialContext
}

func (p *Prober) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return defaultTimeout
}

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}
