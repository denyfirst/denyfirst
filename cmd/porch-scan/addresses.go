package main

import (
	"fmt"
	"io"

	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// printAddresses shows what each of the name's addresses answered when asked
// on its own, where it has more than one.
//
// One row per address, in the words the page uses (R16). Whether they agree is
// said in the notes, once; the rows are what a reader compares to see how.
func printAddresses(w io.Writer, t *tlsprobe.Report) {
	if t == nil || len(t.Addresses) == 0 {
		return
	}
	fmt.Fprint(w, "\n  Each address, asked on its own\n")
	for _, a := range t.Addresses {
		fmt.Fprintf(w, "    %-28s %s\n", a.Address, addressLine(a))
	}
}

// addressLine is one address's row.
func addressLine(a tlsprobe.AddressAnswer) string {
	if !a.Answered {
		return "no answer: " + a.Reason
	}
	return a.Version + " " + a.Suite + ", certificate " + shortFingerprint(a.Certificate)
}

// shortFingerprint is enough of a certificate's SHA-256 to tell two apart on a
// row, the same length the notes use.
func shortFingerprint(sum string) string {
	if sum == "" {
		return "none presented"
	}
	return sum[:min(16, len(sum))] + "…"
}
