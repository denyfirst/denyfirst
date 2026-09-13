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

	fmt.Fprint(w, "\n  Asked with a hand-written hello\n")
	for _, q := range []struct {
		label  string
		answer tlsprobe.LegacyAnswer
	}{
		{"SSL 3.0", l.SSL3},
		{"export", l.Export},
		{"NULL", l.Null},
	} {
		fmt.Fprintf(w, "    %-9s %s\n", q.label, legacyLine(q.answer))
	}
	fmt.Fprintf(w, "    %-9s %s\n", "fallback", fallbackLine(l.Fallback))
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
