package ctlogs

import "testing"

// FuzzReadReceipts feeds the receipt parsers whatever a certificate could carry.
//
// Every length in a receipt, a receipt list and a TBSCertificate is chosen by
// whoever issued the certificate being scanned. None of them may make this
// panic, and a receipt that parses must have a signature that is exactly the
// bytes left, never more.
func FuzzReadReceipts(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 2, 0, 0})
	f.Add(make([]byte, minSCT))
	f.Add([]byte{0x30, 0x03, 0xa3, 0x01, 0x00})

	f.Fuzz(func(t *testing.T, b []byte) {
		if s, err := parseSCT(b); err == nil && len(s.signature) > len(b) {
			t.Errorf("a signature of %d bytes was read from %d", len(s.signature), len(b))
		}
		if scts, err := splitList(b); err == nil {
			for _, sct := range scts {
				if len(sct) > len(b) {
					t.Error("a receipt longer than its list was split out")
				}
			}
		}
		_, _ = precertificateTBS(b)
	})
}
