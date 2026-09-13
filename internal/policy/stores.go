package policy

import "strings"

// What other clients' root stores make of a chain, described and never graded.
//
// The verdict on a chain rests on the store of the machine that ran the scan,
// because that is the store a deployment checked and can stand behind (R7). But
// that is one store among several, and the question an operator actually has is
// whether the people connecting to them will be refused. Mozilla, Chrome,
// Microsoft and Apple each answer that for their own users, from copies of their
// stores dated in the report. None of it moves a verdict: which clients matter is
// the operator's to decide, and a rule choosing for them would be a threshold
// this project invented (R21).

// StoreTrust is what one client's root store makes of a chain.
type StoreTrust struct {
	Store   string `json:"store"`
	Verdict string `json:"verdict"`
	Root    string `json:"root,omitempty"`
	After   string `json:"after,omitempty"`
}

// StoreFacts is what the carried root stores made of a chain.
type StoreFacts struct {
	// Retrieved is the date the carried stores were fetched.
	Retrieved string `json:"retrieved,omitempty"`

	Stores []StoreTrust `json:"stores,omitempty"`

	// Reason says why nothing was established.
	Reason string `json:"reason,omitempty"`
}

// The verdicts, as internal/rootstores writes them.
const (
	storeTrusted     = "trusted"
	storeConditional = "conditional"
	storeDistrusted  = "distrusted"
	storeNotTrusted  = "not-trusted"
)

func (f StoreFacts) named(verdict string) []string {
	var out []string
	for _, s := range f.Stores {
		if s.Verdict == verdict {
			out = append(out, s.Store)
		}
	}
	return out
}

// StoresLine is the one line both faces of a report print for it (R16).
func StoresLine(f StoreFacts) string {
	if len(f.Stores) == 0 {
		return ""
	}

	var parts []string
	if names := f.named(storeTrusted); len(names) > 0 {
		parts = append(parts, "trusted by "+andList(names))
	}
	if names := f.named(storeConditional); len(names) > 0 {
		parts = append(parts, "conditionally by "+andList(names))
	}
	for _, s := range f.Stores {
		if s.Verdict == storeDistrusted {
			parts = append(parts, "distrusted by "+s.Store+" for certificates issued after "+s.After)
		}
	}
	if names := f.named(storeNotTrusted); len(names) > 0 {
		parts = append(parts, "not trusted by "+andList(names))
	}

	line := strings.Join(parts, "; ")
	if f.Retrieved != "" {
		line += " (stores of " + f.Retrieved + ")"
	}
	return line
}

// DescribeStores says what the stores made of the chain, where that needs more
// than the line.
func DescribeStores(f StoreFacts) []Note {
	if f.Reason != "" {
		return []Note{Unsettled("What other clients' root stores make of this chain was not established: " +
			f.Reason + ".")}
	}
	if len(f.Stores) == 0 {
		return nil
	}

	trusted := f.named(storeTrusted)
	if len(trusted) == len(f.Stores) {
		return []Note{Observed(andList(trusted) + " each include a root this chain reaches, as their stores " +
			"stood on " + f.Retrieved + ", so it is not only this machine's store that accepts it.")}
	}

	var out []Note
	if names := f.named(storeNotTrusted); len(names) > 0 {
		out = append(out, Observed(andList(names)+" "+includes(len(names))+" no root this chain reaches, as of "+
			f.Retrieved+", so a client relying on that store refuses the connection whatever the verdict "+
			"above says. The verdict rests on the store of the machine that ran this scan."))
	}
	for _, s := range f.Stores {
		if s.Verdict == storeDistrusted {
			out = append(out, Observed(s.Store+" stopped trusting "+s.Root+" for certificates issued after "+
				s.After+", and this certificate was issued later, so "+s.Store+" refuses it."))
		}
	}
	if names := f.named(storeConditional); len(names) > 0 {
		out = append(out, Unsettled(andList(names)+" "+includes(len(names))+" the root this chain reaches under "+
			"conditions this report does not evaluate — a client version, or a date the store does not publish "+
			"with it — so whether the certificate is accepted there is not established."))
	}
	if len(trusted) > 0 {
		out = append(out, Observed(andList(trusted)+" "+includes(len(trusted))+" a root this chain reaches, as of "+
			f.Retrieved+"."))
	}
	return out
}

func includes(n int) string {
	if n == 1 {
		return "includes"
	}
	return "include"
}

// andList writes "a", "a and b", or "a, b and c".
func andList(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}
