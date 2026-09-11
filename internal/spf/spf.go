// Package spf reads a domain's sender policy and counts what it costs to
// evaluate.
//
// SPF says which servers may send mail claiming to be from a domain. Reading
// the record is easy and is not the useful part: almost every domain has one,
// and the failures that matter are the ones a domain owner cannot see by
// looking at it.
//
// # The ten lookup limit is the finding
//
// RFC 7208 allows at most ten DNS-resolving terms in the evaluation of one
// policy — include, a, mx, ptr, exists, and the redirect modifier — counted
// across everything the record pulls in, not just its own line. A record that
// exceeds it is a permanent error, and a receiver treating a permerror the way
// most do will act as though the domain published **no policy at all**.
//
// That is the shape of the problem worth building a check around. The record
// looks fine. The provider that was added last year looks fine. Nothing in the
// zone file says anything is wrong, and mail that should have been rejected is
// being accepted, or mail that should have been accepted is being marked as
// spam — depending on which side of the limit the receiver falls. The only way
// to see it is to follow every include the way a receiver would and count.
//
// # Nothing is connected to on the mail path
//
// Every term here is resolved with a DNS query and nothing else. No connection
// is made to a mail server, no message is composed, nothing is sent, and
// nothing that would change state at the other end is attempted. The strongest
// privacy story any check in this project has, and it is a property of what SPF
// is rather than a restraint applied to it.
//
// # Counting, not deciding
//
// This does not evaluate a policy against a sending address. Evaluation needs
// an address, a HELO name and a sender to judge, and answering "would this
// message pass" for a message nobody sent is a question about nothing. What is
// counted is what a receiver would have to do, which is the part that can be
// wrong before any message exists.
package spf

import (
	"context"
	"strings"
)

const (
	// maxLookups is RFC 7208's limit on DNS-resolving terms in one evaluation.
	// Exceeding it is a permanent error, which receivers read as no policy.
	maxLookups = 10

	// maxVoidLookups is the limit on lookups that return nothing. Two,
	// deliberately low: a policy built on names that no longer resolve is a
	// policy nobody is maintaining, and RFC 7208 treats the third as fatal.
	maxVoidLookups = 2

	// maxDepth bounds recursion through include and redirect.
	//
	// The lookup budget already bounds the work, but a record that includes
	// itself would recurse before spending it. Ten is past anything real: a
	// chain that deep has already exceeded the lookup limit.
	maxDepth = 10

	// maxRecordLength bounds one record before it is parsed. A policy is a few
	// hundred bytes; this sits well above that and refuses to walk whatever a
	// stranger's zone announces.
	maxRecordLength = 4096

	// maxTerms bounds the terms read from one record, for the same reason.
	maxTerms = 128
)

// Resolver is the lookup this package needs.
//
// The narrowest shape that does the job, and an interface so this package does
// not decide how DNS is spoken — the same argument internal/verify makes. It
// answers whether the name exists separately from what it holds, because a
// lookup that found nothing and a name that does not exist are both void for
// the purposes of the limit and are different facts everywhere else.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) (values []string, existed bool, err error)
}

// Qualifier is what a policy says about senders it does not list.
type Qualifier string

const (
	// Fail is "-all": everything not listed is forged. The only value that
	// tells a receiver it may reject.
	Fail Qualifier = "-"

	// SoftFail is "~all": mark it, do not refuse it. A staging position, and
	// the one most domains stop at.
	SoftFail Qualifier = "~"

	// Neutral is "?all": the domain declines to say. It has the same effect on
	// a receiver as publishing nothing.
	Neutral Qualifier = "?"

	// Pass is "+all": everybody may send as this domain. There is no
	// arrangement that wants this.
	Pass Qualifier = "+"
)

// Facts is what reading one domain's policy established.
//
// Facts and not a verdict. What counts as an acceptable qualifier is a policy
// decision that belongs in internal/policy beside every other one, and what
// counts as too many lookups is RFC 7208's decision rather than this project's.
type Facts struct {
	// Records is how many TXT records at the domain announce themselves as SPF.
	//
	// More than one is not a stricter policy: RFC 7208 makes it a permanent
	// error, so a domain that published a second record to add a provider has
	// switched its policy off. It is the commonest way to break SPF while
	// appearing to strengthen it.
	Records int

	// Found is true when exactly one record was there to evaluate.
	Found bool

	// Raw is the record, bounded. Empty when there was not exactly one.
	Raw string

	// All is the qualifier on the all mechanism, empty when the record has
	// none — which leaves a receiver with the default, neutral, and is the same
	// outcome as publishing nothing.
	All Qualifier

	// Lookups is how many DNS-resolving terms a receiver would evaluate,
	// counted across every include and redirect the policy pulls in.
	Lookups int

	// LookupLimit is true when Lookups exceeded what RFC 7208 allows. The
	// policy is then a permanent error, and a receiver reads that as no policy.
	LookupLimit bool

	// VoidLookups counts lookups that found nothing, and VoidLimit is true when
	// there were more than RFC 7208 allows.
	VoidLookups int
	VoidLimit   bool

	// UsesPTR is true when any record in the chain uses the ptr mechanism,
	// which RFC 7208 says SHOULD NOT be used: it is slow, it loads the
	// receiver, and several large receivers ignore it.
	UsesPTR bool

	// Includes names the domains this policy pulls in, in the order they were
	// first seen and bounded. The list is what an operator works from when the
	// count is too high: the answer is nearly always one provider too many.
	Includes []string

	// Reason says why nothing was established, in this package's own words.
	// Empty when the policy was read.
	Reason string
}

// Check reads a domain's policy and counts what evaluating it would cost.
func Check(ctx context.Context, r Resolver, domain string) Facts {
	domain = fold(domain)
	if domain == "" {
		return Facts{Reason: "no domain was given"}
	}
	if r == nil {
		return Facts{Reason: "no resolver was configured to ask"}
	}

	w := &walk{resolver: r, seen: map[string]bool{}}

	record, facts := w.recordFor(ctx, domain)
	if facts.Reason != "" || !facts.Found {
		return facts
	}

	facts.Raw = record
	w.evaluate(ctx, domain, record, 0, &facts)

	facts.LookupLimit = facts.Lookups > maxLookups
	facts.VoidLimit = facts.VoidLookups > maxVoidLookups
	return facts
}

// walk carries the state one evaluation accumulates.
type walk struct {
	resolver Resolver

	// seen stops a policy that includes itself, directly or around a loop.
	// The lookup budget would stop it too, eventually; this stops it before
	// the recursion rather than after.
	seen map[string]bool
}

// recordFor finds the one SPF record at a name, or says why there is not one.
func (w *walk) recordFor(ctx context.Context, domain string) (string, Facts) {
	values, existed, err := w.resolver.LookupTXT(ctx, domain)
	if err != nil {
		// The underlying error names resolvers and addresses, so only the
		// shape of the failure is reported (I6).
		return "", Facts{Reason: "the domain's TXT records could not be read"}
	}
	if !existed {
		return "", Facts{Reason: "the domain does not exist"}
	}

	var found []string
	for _, v := range values {
		if isPolicy(v) {
			found = append(found, v)
		}
	}

	out := Facts{Records: len(found)}
	switch len(found) {
	case 0:
		return "", out
	case 1:
		out.Found = true
		return bound(found[0]), out
	default:
		// Not an error to report as a failure to read: the records were read,
		// and what they say is that this domain's policy is a permanent error.
		// A caller grades that; this says what is there.
		return "", out
	}
}

// evaluate walks one record, counting what a receiver would have to resolve.
func (w *walk) evaluate(ctx context.Context, domain, record string, depth int, facts *Facts) {
	if depth > maxDepth || w.seen[domain] {
		return
	}
	w.seen[domain] = true

	redirect := ""

	for i, term := range strings.Fields(record) {
		if i > maxTerms {
			return
		}
		if i == 0 && strings.EqualFold(term, "v=spf1") {
			continue
		}

		name, mechanism, qualifier := split(term)

		switch mechanism {
		case "all":
			// Only the outermost record's all is the domain's answer. An all
			// inside an include is never reached: RFC 7208 says a match
			// inside an include is a match and a no-match is a no-match, and
			// its all cannot produce either.
			if depth == 0 && facts.All == "" {
				facts.All = qualifier
			}

		case "include":
			facts.Lookups++
			if name == "" {
				continue
			}
			facts.rememberInclude(name)

			included, sub := w.recordFor(ctx, name)
			if sub.Reason != "" || !sub.Found {
				// A name that answered nothing is a void lookup, which RFC
				// 7208 bounds separately and low: a policy resting on names
				// that no longer resolve is a policy nobody is maintaining.
				facts.VoidLookups++
				continue
			}
			w.evaluate(ctx, name, included, depth+1, facts)

		case "redirect":
			// Counted here and followed after the loop, because redirect only
			// applies when no mechanism matched — so a record carrying both
			// all and redirect ignores the redirect entirely, and counting it
			// as though it were followed would overstate the cost.
			if name != "" {
				redirect = name
			}

		case "a", "mx", "exists":
			// One lookup each, whether or not this evaluates them: the count
			// is what a receiver would spend, not what this program spends.
			facts.Lookups++

		case "ptr":
			facts.Lookups++
			facts.UsesPTR = true
		}
	}

	if redirect != "" && facts.All == "" {
		facts.Lookups++
		facts.rememberInclude(redirect)

		target, sub := w.recordFor(ctx, redirect)
		if sub.Reason != "" || !sub.Found {
			facts.VoidLookups++
			return
		}
		w.evaluate(ctx, redirect, target, depth+1, facts)
	}
}

// rememberInclude keeps the domains a policy pulls in, bounded and in order.
func (f *Facts) rememberInclude(name string) {
	if len(f.Includes) >= maxTerms {
		return
	}
	for _, have := range f.Includes {
		if have == name {
			return
		}
	}
	f.Includes = append(f.Includes, name)
}

// isPolicy reports whether a TXT value announces itself as an SPF record.
//
// The version tag is compared case-insensitively and must be the whole first
// token: "v=spf10" is not a policy, and a record beginning with the words in a
// sentence is not one either.
func isPolicy(value string) bool {
	fields := strings.Fields(strings.TrimSpace(value))
	return len(fields) > 0 && strings.EqualFold(fields[0], "v=spf1")
}

// split reads one term into its qualifier, mechanism and name.
//
// A term is an optional qualifier, a mechanism, and for some mechanisms a
// value after ":" or "=". Case is insignificant in the mechanism and in the
// version tag; the name after it is a domain and is folded for the same reason
// every other name in this project is (I7).
func split(term string) (name, mechanism string, qualifier Qualifier) {
	qualifier = Fail

	switch {
	case strings.HasPrefix(term, "+"):
		qualifier, term = Pass, term[1:]
	case strings.HasPrefix(term, "-"):
		qualifier, term = Fail, term[1:]
	case strings.HasPrefix(term, "~"):
		qualifier, term = SoftFail, term[1:]
	case strings.HasPrefix(term, "?"):
		qualifier, term = Neutral, term[1:]
	default:
		// No qualifier means pass, which is what makes a bare "all" as
		// permissive as "+all" and is worth getting right: a record ending in
		// "all" tells a receiver that everybody may send.
		qualifier = Pass
	}

	// ":" separates a mechanism from its value and "=" separates a modifier
	// from its value. Splitting on whichever comes first reads both without
	// two passes.
	cut := strings.IndexAny(term, ":=")
	if cut < 0 {
		return "", strings.ToLower(term), qualifier
	}
	return fold(term[cut+1:]), strings.ToLower(term[:cut]), qualifier
}

// bound truncates a record before it is kept or shown.
func bound(s string) string {
	if len(s) > maxRecordLength {
		return s[:maxRecordLength]
	}
	return s
}

// fold reduces a name the way every other comparison in this project does (I7).
func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
