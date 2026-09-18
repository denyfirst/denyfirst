package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/denyfirst/porch/internal/mailscan"
	"github.com/denyfirst/porch/internal/scan"
	"github.com/denyfirst/porch/internal/verify"
)

// The verification endpoint: what a domain has to publish for this deployment
// to scan it, and whether it has.
//
// Until this existed the token was printed by porchd -verification-token on the
// operator's machine, so the person at the page was told to publish a record
// only the operator could look up. The page now asks, shows the record, and
// asks again once it is published.
//
// Handing out a token is safe, and the reason is the design of the token
// rather than anything here. It is derived from this deployment's secret and
// the one domain, so it is worth something only to whoever can publish it in
// that domain's zone — which is the thing being proven. Copying it to another
// domain proves nothing, because that domain's token is a different value, and
// another deployment's token for the same domain is a different value again,
// because its secret is. Knowing the token is not the proof; publishing it is.

// verifyRecord is one place a proof can be published.
type verifyRecord struct {
	// Domain is the name the proof covers: itself and every name beneath it.
	Domain string `json:"domain"`

	// Name is where the TXT record goes, and Value what it carries.
	Name  string `json:"name"`
	Value string `json:"value"`
}

type verifyResponse struct {
	// Required is false on a deployment that scans without proof, and nothing
	// else is sent then.
	Required bool `json:"required"`

	// Verified is whether a proof covering the name is published now.
	Verified bool `json:"verified"`

	// Records are the places a proof may go, most specific first: the name
	// itself, then each domain above it down to two labels. A record at a
	// parent covers the name too, and which one to use is the operator's
	// call — this service cannot tell a registrable domain from a public
	// suffix, and does not guess.
	Records []verifyRecord `json:"records,omitempty"`
}

// maxVerifyRecords bounds the list. A name has at most this many domains above
// it that anybody would publish under.
const maxVerifyRecords = 4

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	// Every guard a scan has, spending the proof allowance rather than the
	// scan one: the Domains page asks once per domain, and a list of five
	// used to leave nothing to scan with (audit 2026-09-18, D04).
	t, ok := s.admit(w, r, parseVerifyTarget, s.proofs,
		"Too many proof checks from this address. Try again shortly.")
	if !ok {
		return
	}

	scope := s.scanner.Verify
	if scope == nil {
		writeJSON(w, http.StatusOK, verifyResponse{Required: false})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.limits.RequestTimeout)
	defer cancel()

	// And a slot of its own, so the lookups in flight are bounded however
	// many clients ask (D10), without a cheap lookup holding a scan's slot.
	// A request whose deadline passes while queued is released unanswered.
	if err := s.proofSem.acquire(ctx); err != nil {
		w.Header().Set("Retry-After", "5")
		s.refuse(w, http.StatusServiceUnavailable, "too_busy",
			"Too many proof checks are in flight. Try again shortly.")
		return
	}
	defer s.proofSem.release()

	// The zone proof, which is what every check accepts. The file proof
	// covers only the web check and is not offered here: a record the page
	// tells somebody to publish has to be one that works for whatever they
	// tick.
	err := scope.Covers(ctx, t.host, verify.AnyPort)
	switch {
	case err == nil:
	case errors.Is(err, verify.ErrNotVerified):
	default:
		// The lookup failed, which is not the domain being unverified.
		// Telling somebody to publish a record they may already have
		// published would send them to the wrong place. The error can name
		// resolver internals, so only its shape is returned.
		s.refuse(w, http.StatusBadGateway, "scan_failed",
			"The challenge record could not be looked up. Try again shortly.")
		return
	}

	out := verifyResponse{Required: true, Verified: err == nil}
	labels := strings.Split(t.host, ".")
	for i := 0; i+1 < len(labels) && len(out.Records) < maxVerifyRecords; i++ {
		domain := strings.Join(labels[i:], ".")
		out.Records = append(out.Records, verifyRecord{
			Domain: domain,
			Name:   verify.Label + "." + domain,
			Value:  verify.Token(scope.Secret, domain),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// parseVerifyTarget takes what any check takes: a name, optionally with a
// port, or a mail address. What is proven is the name.
func parseVerifyTarget(raw string) (target, *refusal) {
	raw, _ = mailscan.DropLocalPart(raw)

	host, _, _, err := scan.SplitTargetPort(raw)
	if err != nil {
		return target{}, &refusal{http.StatusBadRequest, "invalid_target",
			"The target must be a hostname, and must not contain spaces or control characters."}
	}
	if refused := refuseAnAddress(host); refused != nil {
		return target{}, refused
	}
	// A single label has nothing above it to publish under. SplitTargetPort
	// already refuses one, which is why no check here repeats it: a second
	// check escaped every sabotage on 2026-09-17, because it could not fire.
	return target{host: host, scope: scan.DefaultPort}, nil
}
