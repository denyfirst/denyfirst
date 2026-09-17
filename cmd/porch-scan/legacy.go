package main

import (
	"fmt"
	"io"

	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// printLegacyVersion adds SSL 3.0 to the version rows.
//
// Beside the others rather than in a section of its own, because a reader
// scanning the version list for the obsolete one looks there. The words are the
// ones the other rows use, for the same reason: "refused" only where the server
// said no, "not measured" everywhere else (R4).
func printLegacyVersion(w io.Writer, l tlsprobe.Legacy) {
	if !l.Asked {
		return
	}

	a := l.SSL3
	switch {
	case a.Accepted && a.VersionGrade != nil && a.Suite != nil:
		// With the suite, since this is the only row SSL 3.0 has.
		fmt.Fprintf(w, "    %-9s accepted       %s  %s\n", "SSL 3.0", a.VersionGrade.Verdict, a.Suite.Name)
	case a.Accepted && a.VersionGrade != nil:
		fmt.Fprintf(w, "    %-9s accepted       %s\n", "SSL 3.0", a.VersionGrade.Verdict)
	case a.Accepted:
		// Accepted at a version other than SSL 3.0 cannot reach here — the
		// SSL 3.0 hello claims nothing higher — but a row that printed
		// "accepted" with no grade would be the one row a reader could not
		// check, so it says what it knows.
		fmt.Fprintf(w, "    %-9s accepted       at %s\n", "SSL 3.0", a.Version)
	case a.Refused:
		fmt.Fprintf(w, "    %-9s refused\n", "SSL 3.0")
	default:
		fmt.Fprintf(w, "    %-9s not measured   %s\n", "SSL 3.0", a.Reason)
	}
}

// printLegacySuites shows what the hand-written hellos were answered with.
//
// Labelled as asked by hand, because these rows are not an enumeration and a
// reader who took "export refused" for "no export suite is accepted" would be
// reading one hello as every hello. It is one hello offering every export suite
// at once, which is what "any of each" in the standing limit means.
func printLegacySuites(w io.Writer, l tlsprobe.Legacy) {
	if !l.Asked {
		return
	}

	// Titled for what it is, and SSL 3.0 left in the version list. The old
	// title, "Asked with a hand-written hello", over a list that repeated
	// SSL 3.0, read as a second list of versions.
	fmt.Fprint(w, "\n  Obsolete suites, asked for directly\n")
	// Why they are asked this way is for -limits to say; the note says how to
	// read a row.
	fmt.Fprint(w, "    Each family was offered on its own, every suite in it at once.\n")
	fmt.Fprint(w, "    Refused means the server accepted none of them.\n")
	for _, q := range []struct {
		label  string
		answer tlsprobe.LegacyAnswer
	}{
		{"Export-grade", l.Export},
		{"NULL, no encryption", l.Null},
		{"Finite-field DHE", l.FFDHE},
		{"Anonymous, no certificate", l.Anonymous},
	} {
		fmt.Fprintf(w, "    %-26s %s\n", q.label, legacyLine(q.answer))
	}
	fmt.Fprintf(w, "    %-26s %s\n", "Downgrade signal", fallbackLine(l.Fallback))
}

func legacyLine(a tlsprobe.LegacyAnswer) string {
	switch {
	case a.Accepted && a.Suite != nil:
		return fmt.Sprintf("accepted       %s  %s at %s", a.Suite.Verdict, a.Suite.Name, a.Version)
	case a.Accepted:
		return "accepted       at " + a.Version
	case a.Refused:
		return "refused"
	default:
		return "not measured   " + a.Reason
	}
}

func fallbackLine(f tlsprobe.Fallback) string {
	switch {
	case f.Measured && f.Honoured:
		return "honoured       a hello claiming only " + f.Asked + " was refused"
	case f.Measured:
		return "not honoured   a hello claiming only " + f.Asked + " was answered"
	default:
		return "not measured   " + f.Reason
	}
}
