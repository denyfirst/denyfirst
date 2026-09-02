package tlsprobe

import "sync"

// The addresses one probe actually reached.
//
// A full scan of a modern host is thirteen separate TCP connections, and each
// one resolves the name again. A name with several addresses therefore does
// not have to hand them all to the same machine: most recursive resolvers
// rotate the order of an answer set, so handshake two can land somewhere
// handshake one did not.
//
// Until 2026-09-02 nothing noticed. The report recorded the address of the
// newest version that answered, printed it at the top, and merged every
// measurement below it into one picture — so a cipher table could hold rows
// from two machines while naming one, and the certificate described could
// have come from a third. Nothing was false in any single row. The report as
// a whole claimed to describe one server, and could not tell whether it did.
//
// This is what the report needed and did not have: the set of addresses the
// handshakes actually reached. Collected here rather than by the callers,
// because a call site that forgets to record its address is a call site that
// silently narrows the claim.
//
// Per probe, never on the Prober: one Prober serves every scan the service
// runs, and state on it would mix one visitor's scan into another's.
type addressSet struct {
	mu    sync.Mutex
	seen  map[string]bool
	order []string
}

func newAddressSet() *addressSet {
	return &addressSet{seen: make(map[string]bool)}
}

// add records an address a handshake reached. Empty is ignored: a handshake
// that never connected reached nothing.
func (s *addressSet) add(addr string) {
	if s == nil || addr == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[addr] {
		return
	}
	s.seen[addr] = true
	s.order = append(s.order, addr)
}

// list returns them in the order they were first reached.
func (s *addressSet) list() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.order...)
}
