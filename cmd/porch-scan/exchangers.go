package main

import (
	"fmt"
	"io"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// printExchangers shows what each exchanger answered when asked for encryption.
//
// One row per exchanger under the MX list they came from, in the same words the
// page uses (R16). The states are kept apart on each row because each sends a
// reader somewhere different: an exchanger that could not be reached, one that
// offers no encryption, one whose certificate fails, and one that is fine.
func printExchangers(w io.Writer, f *policy.MailFacts) {
	if len(f.MXHosts) == 0 {
		return
	}
	if !f.ExchangersContacted {
		if f.ExchangersReason != "" {
			fmt.Fprintf(w, "    STARTTLS   not measured: %s\n", f.ExchangersReason)
		}
		return
	}
	for _, x := range f.Exchangers {
		fmt.Fprintf(w, "    STARTTLS   %s: %s\n", x.Host, exchangerLine(x))
	}
}

// exchangerLine is one exchanger's row.
func exchangerLine(x policy.ExchangerTLS) string {
	switch {
	case !x.Measured && x.ConnectTimedOut:
		// Short on the row. The full sentence — that many networks block
		// outbound port 25, so this likely describes where the scan ran — is
		// said once in the notes, and repeating it on every exchanger buried
		// the rows it was printed on.
		return "not measured: port 25 could not be reached from here"
	case !x.Measured:
		return "not measured: " + x.Reason
	case !x.Offered:
		return "not offered"
	case !x.Upgraded:
		return "offered, not negotiated: " + x.Reason
	case !x.Trusted:
		return x.Version + " " + x.Suite + ", certificate does not verify: " + x.CertificateReason
	case !x.NameMatches:
		return x.Version + " " + x.Suite + ", certificate does not name this exchanger"
	default:
		return x.Version + " " + x.Suite + ", certificate verifies"
	}
}
