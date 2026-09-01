package policy

// A note is something a report says that is not a verdict, and there are
// three kinds of them.
//
// Until 2026-09-01 there was one kind: a string, in one list, under one
// heading — "What this did not measure". Three different sentences lived
// there. A scan of kapitalbank.az produced eleven notes: three were limits of
// that scan, three were standing properties of this program, and five were
// things it had established and chosen not to grade. Among the five was the
// post-quantum key exchange, which had been measured, had passed, and was
// filed under a heading saying it had not been measured.
//
// Nothing in that report was false. The framing was, which is the same defect
// in a later place: a reader takes the heading, and the heading was wrong for
// most of what it covered. It also made a report that establishes a great deal
// read as though it established nothing.
//
// The kind is chosen where the sentence is written, by the code that knows
// which it is. Deciding it afterwards by reading the finished prose would put
// the sentence and its label in two different places, which is how they come
// apart.
type NoteKind string

const (
	// KindObserved: established by this scan and deliberately not graded.
	// This is a result. It belongs beside the findings, not below them.
	KindObserved NoteKind = "observed"

	// KindUnsettled: this scan could not settle it, for a reason that lies
	// with this host or this attempt — it stopped answering, it offers only
	// one version, it sent a field that could not be parsed. It qualifies
	// this verdict and has to travel with it.
	KindUnsettled NoteKind = "unsettled"

	// KindStanding: true of every scan this program runs. A property of the
	// instrument, not of the host, so it says nothing about this one and
	// repeating it on every report is how it stops being read.
	KindStanding NoteKind = "standing"
)

// Note is one sentence and the kind of claim it makes.
type Note struct {
	Kind NoteKind `json:"kind"`
	Text string   `json:"text"`
}

// Observed records something this scan established and does not grade.
func Observed(text string) Note { return Note{Kind: KindObserved, Text: text} }

// Unsettled records something this scan could not establish about this host.
func Unsettled(text string) Note { return Note{Kind: KindUnsettled, Text: text} }

// Standing records a limit that applies to every scan this program runs.
func Standing(text string) Note { return Note{Kind: KindStanding, Text: text} }

// NotesOfKind selects one kind, keeping the order the notes were made in.
//
// Both renderers call this rather than sorting or filtering for themselves.
// The report has two faces and they have to say the same thing in the same
// order; giving each its own selection is how they drift apart.
func NotesOfKind(notes []Note, kind NoteKind) []Note {
	var out []Note
	for _, n := range notes {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

// Texts is the sentences alone, for a caller that has already chosen a kind.
func Texts(notes []Note) []string {
	out := make([]string, 0, len(notes))
	for _, n := range notes {
		out = append(out, n.Text)
	}
	return out
}
