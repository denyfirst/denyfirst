package tlsprobe

import (
	"context"
	"crypto/tls"
	"sync"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/rawhello"
)

// tls13NotEnumerated is said when the hand-written hellos could not be trusted
// to answer the question, and only the suite Go negotiated is listed.
const tls13NotEnumerated = "The TLS 1.3 suites were not asked one by one: a hand-written hello offering the " +
	"suite this scan's own handshake negotiated was not answered the way that handshake was, so a refusal " +
	"of the others would say nothing about them. Only the negotiated suite is listed."

// tls13Suites asks which of the registry's TLS 1.3 suites the server accepts,
// one hello per suite.
//
// # Why by hand
//
// Go's client offers the TLS 1.3 suites it chooses and gives a caller no way to
// offer others, so until this existed a TLS 1.3 server was listed with the one
// suite it negotiated — and one accepting the integrity-only suites of RFC 9150,
// which send every record in the clear, was reported as strong.
//
// # When the answers are believed
//
// A hello Go did not write can fail for reasons of its own — a server that
// wants an extension this one does not send, a middlebox that drops what it
// does not recognise — and every such failure would read as a suite refused. So
// the suite Go's own handshake negotiated is asked too, and unless the server
// accepts it at TLS 1.3 here, none of the answers is used: the negotiated suite
// alone is listed, as before, and the report says why (R4).
//
// Once calibrated, an acceptance is believed only at TLS 1.3 with the suite
// offered; a refusal is a refusal; anything else leaves the list incomplete,
// which is what CipherListComplete exists to say.
func (p *Prober) tls13Suites(ctx context.Context, host, port string, negotiated uint16, reached *addressSet) (ciphers []CipherResult, complete bool, reason string) {
	answers := make([]rawhello.Result, len(rawhello.TLS13))

	var wg sync.WaitGroup
	for i, s := range rawhello.TLS13 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i] = p.rawAsk(ctx, host, port, rawhello.Hello{
				RecordVersion: policy.VersionTLS10,
				ClientVersion: policy.VersionTLS12,
				Suites:        []uint16{s.ID},
				TLS13:         true,
				ServerName:    host,
			}, reached)
		}()
	}
	wg.Wait()

	complete = true
	calibrated := false
	for i, s := range rawhello.TLS13 {
		got := answers[i]
		switch {
		case got.Answer == rawhello.Accepted && got.Suite == s.ID && got.Version == tls.VersionTLS13:
			ciphers = append(ciphers, CipherResult{ID: s.ID, CipherFinding: policy.GradeCipher(s.Name)})
			if s.ID == negotiated {
				calibrated = true
			}
		case got.Answer == rawhello.Refused:
		default:
			complete = false
		}
	}

	if !calibrated {
		return []CipherResult{gradeCipher(negotiated)}, true, tls13NotEnumerated
	}
	return ciphers, complete, ""
}
