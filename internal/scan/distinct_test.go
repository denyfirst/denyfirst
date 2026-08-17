package scan

import "testing"

// The function that fixed the count, and until now the only thing that had
// never been asked to prove it works.
//
// The defect was that a log count taken from the certificate alone was printed
// as though it described the timestamps from both routes. The fix unions the
// two sets. Both hosts that exercise this in the field name disjoint sets, so
// the union happens to equal the sum on every live example available — which
// means the deduplication, the actual point of the change, is covered here and
// nowhere else.
func TestDistinctLogsCountsEachLogOnce(t *testing.T) {
	const (
		a = "aaaa"
		b = "bbbb"
		c = "cccc"
		d = "dddd"
	)

	cases := []struct {
		name string
		sets [][]string
		want int
	}{
		{
			// The case both live vectors show: a certificate and its
			// handshake naming different logs. Union equals sum here, which
			// is why this case cannot demonstrate that a union is happening.
			name: "disjoint sets add up",
			sets: [][]string{{a, b}, {c, d}},
			want: 4,
		},
		{
			// The case the defect produced, in reverse. Adding two counts
			// would report five logs where there are three.
			name: "a log named by both routes is counted once",
			sets: [][]string{{a, b, c}, {b, c}},
			want: 3,
		},
		{
			name: "identical sets collapse to one",
			sets: [][]string{{a, b}, {a, b}},
			want: 2,
		},
		{
			// A certificate with no timestamps at all still has to produce a
			// number rather than a panic.
			name: "nothing at all",
			sets: [][]string{nil, nil},
			want: 0,
		},
		{
			name: "one route empty",
			sets: [][]string{{a, b}, nil},
			want: 2,
		},
		{
			// The parsers deduplicate within their own set already, so this
			// should not arrive. Counting it correctly anyway means the two
			// defences do not have to agree about whose job it is.
			name: "a repeat inside one set",
			sets: [][]string{{a, a, b}, {b}},
			want: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := distinctLogs(tc.sets...); got != tc.want {
				t.Errorf("distinctLogs(%v) = %d, want %d", tc.sets, got, tc.want)
			}
		})
	}
}

// Called with nothing, which is what happens for a scan that reached no
// certificate.
func TestDistinctLogsOfNothing(t *testing.T) {
	if got := distinctLogs(); got != 0 {
		t.Errorf("distinctLogs() = %d, want 0", got)
	}
}
