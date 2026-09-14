package rawhello

import (
	"bytes"
	"testing"
)

// FuzzReadReply feeds the parser whatever a server could send.
//
// The reply is written by whoever is being measured, so the two properties that
// matter are the ones a hostile server would attack: that nothing it sends
// makes this panic, and that nothing it sends makes this read further than the
// answer needs. A third follows from R4 — an answer that is not an acceptance
// never carries a version or a suite somebody could render as one.
func FuzzReadReply(f *testing.F) {
	f.Add(serverHello(0x0303, 0x0003, 0))
	f.Add(serverHello(0x0300, 0x000A, 32))
	f.Add(record(contentAlert, []byte{alertFatal, 40}))
	f.Add(record(contentAlert, []byte{1, 0}))
	f.Add([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	f.Add([]byte{contentHandshake, 3, 1, 0xFF, 0xFF})
	f.Add([]byte{})
	f.Add(serverHelloWith(0x0303, 0x1301, make([]byte, 32), supportedTLS13))

	limit := 5 + 4 + serverHelloFixed + maxSessionID + 2 + 3 + maxExtensions

	f.Fuzz(func(t *testing.T, reply []byte) {
		c := &countingReader{r: bytes.NewReader(reply)}
		got := ReadReply(c)

		if c.read > limit {
			t.Errorf("%d bytes were read, and no answer needs more than %d", c.read, limit)
		}
		if got.Answer != Accepted && (got.Version != 0 || got.Suite != 0) {
			t.Errorf("a reply read as %s carries version %#04x and suite %#04x", got.Answer, got.Version, got.Suite)
		}
		if got.Answer == Unanswered && got.Err == nil {
			t.Error("an unanswered reply carries no reason")
		}
	})
}
